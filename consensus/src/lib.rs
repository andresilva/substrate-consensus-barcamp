use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use codec::{Decode, Encode};
use derive_more::{AsRef, From, Into};
use futures::{future, FutureExt, StreamExt};
use log::{debug, info, warn};
use parking_lot::Mutex;

use sc_client_api::{Backend as BackendT, BlockchainEvents, Finalizer};
use sc_network_gossip::{
    GossipEngine, Network as GossipNetwork, ValidationResult as GossipValidationResult,
    Validator as GossipValidator, ValidatorContext as GossipValidatorContext,
};
use sp_api::{BlockId, ProvideRuntimeApi, TransactionFor};
use sp_application_crypto::RuntimePublic;
use sp_consensus::{
    import_queue::{BasicQueue, CacheKeyId, Verifier},
    BlockCheckParams, BlockImport, BlockImportParams, BlockOrigin, Environment as EnvironmentT,
    Error as ConsensusError, ForkChoiceStrategy, ImportResult, Proposal, Proposer, RecordProof,
    SelectChain as SelectChainT, SyncOracle as SyncOracleT,
};
use sp_core::{sr25519, Pair};
use sp_runtime::{
    generic::DigestItem,
    traits::{Block as BlockT, Hash as HashT, Header as HeaderT},
    ConsensusEngineId, Justification,
};

pub const SINGLETON_ENGINE_ID: ConsensusEngineId = *b"SGTN";
pub const SINGLETON_PROTOCOL_NAME: &[u8] = b"/barcamp/singleton/1";

#[derive(AsRef, Clone, From, Into)]
pub struct SingletonBlockAuthority(sr25519::Public);

#[derive(AsRef, From, Into)]
pub struct SingletonBlockAuthorityPair(sr25519::Pair);

#[derive(AsRef, Clone, From, Into)]
pub struct SingletonFinalityAuthority(sr25519::Public);

#[derive(AsRef, From, Into)]
pub struct SingletonFinalityAuthorityPair(sr25519::Pair);

#[derive(AsRef, Decode, Encode, From)]
struct SingletonFinalityJustification(sr25519::Signature);

#[derive(AsRef, Decode, Encode, From)]
struct SingletonSeal(sr25519::Signature);

impl<Block> From<SingletonSeal> for DigestItem<Block> {
    fn from(seal: SingletonSeal) -> Self {
        DigestItem::Seal(SINGLETON_ENGINE_ID, seal.encode())
    }
}

struct SingletonVerifier<Block> {
    authority: SingletonBlockAuthority,
    _phantom: PhantomData<Block>,
}

impl<Block> SingletonVerifier<Block>
where
    Block: BlockT,
{
    fn check_header(&self, header: &mut Block::Header) -> Result<SingletonSeal, String> {
        let seal = match header.digest_mut().pop() {
            Some(DigestItem::Seal(id, seal)) => {
                if id == SINGLETON_ENGINE_ID {
                    SingletonSeal::decode(&mut &seal[..])
                        .map_err(|_| "Header with invalid seal".to_string())?
                } else {
                    return Err("Header seal for wrong engine".into());
                }
            }
            _ => return Err("Unsealed header".into()),
        };

        let pre_hash = header.hash();
        if !self.authority.as_ref().verify(&pre_hash, seal.as_ref()) {
            return Err("Invalid seal signature.".into());
        }

        Ok(seal)
    }
}

impl<Block> Verifier<Block> for SingletonVerifier<Block>
where
    Block: BlockT,
{
    fn verify(
        &mut self,
        origin: BlockOrigin,
        mut header: Block::Header,
        justification: Option<Justification>,
        body: Option<Vec<Block::Extrinsic>>,
    ) -> Result<
        (
            BlockImportParams<Block, ()>,
            Option<Vec<(CacheKeyId, Vec<u8>)>>,
        ),
        String,
    > {
        let hash = header.hash();
        let seal = self.check_header(&mut header)?;

        let mut import_params = BlockImportParams::new(origin, header);

        import_params.body = body;
        import_params.post_digests.push(seal.into());
        import_params.post_hash = Some(hash);

        import_params.justification = justification;
        import_params.finalized = false;

        import_params.fork_choice = Some(ForkChoiceStrategy::LongestChain);

        Ok((import_params, None))
    }
}

struct SingletonBlockImport<Inner, Client> {
    inner: Inner,
    finality_authority: SingletonFinalityAuthority,
    _phantom: PhantomData<Client>,
}

impl<Block, Inner, Client> BlockImport<Block> for SingletonBlockImport<Inner, Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Inner: BlockImport<Block, Transaction = TransactionFor<Client, Block>>,
    Inner::Error: Into<ConsensusError>,
{
    type Error = ConsensusError;
    type Transaction = TransactionFor<Client, Block>;

    fn check_block(&mut self, block: BlockCheckParams<Block>) -> Result<ImportResult, Self::Error> {
        self.inner.check_block(block).map_err(Into::into)
    }

    fn import_block(
        &mut self,
        mut block: BlockImportParams<Block, Self::Transaction>,
        new_cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {
        let justification = block
            .justification
            .take()
            .and_then(|j| SingletonFinalityJustification::decode(&mut &j[..]).ok());

        if let Some(justification) = justification {
            let hash = block
                .post_hash
                .as_ref()
                .expect("header has seal; must have post hash; qed.");

            if self
                .finality_authority
                .as_ref()
                .verify(hash, justification.as_ref())
            {
                block.justification = Some(justification.encode());
                block.finalized = true;
            } else {
                warn!(target: "singleton", "Invalid justification provided with block: {:?}", hash)
            }
        }

        self.inner
            .import_block(block, new_cache)
            .map_err(Into::into)
    }
}

#[derive(Clone)]
pub struct SingletonConfig {
    pub block_authority: SingletonBlockAuthority,
    pub finality_authority: SingletonFinalityAuthority,
}

pub type SingletonImportQueue<Block, Client> = BasicQueue<Block, TransactionFor<Client, Block>>;

pub fn import_queue<Block, Inner, Client>(
    config: SingletonConfig,
    inner: Inner,
    _client: Arc<Client>,
    spawner: &impl sp_core::traits::SpawnNamed,
) -> SingletonImportQueue<Block, Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + Send + Sync + 'static,
    Inner: BlockImport<Block, Transaction = TransactionFor<Client, Block>> + Send + Sync + 'static,
    Inner::Error: Into<ConsensusError>,
{
    let block_import = Box::new(SingletonBlockImport {
        inner,
        finality_authority: config.finality_authority,
        _phantom: PhantomData::<Client>,
    });

    let verifier = SingletonVerifier {
        authority: config.block_authority,
        _phantom: PhantomData,
    };

    BasicQueue::new(verifier, block_import, None, None, spawner, None)
}

pub fn start_singleton_block_author<Block, Client, Inner, Environment, SelectChain, SyncOracle>(
    authority_key: SingletonBlockAuthorityPair,
    mut inner: Inner,
    _client: Arc<Client>,
    mut environment: Environment,
    select_chain: SelectChain,
    mut sync_oracle: SyncOracle,
) where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + Send + Sync + 'static,
    Inner: BlockImport<Block, Transaction = TransactionFor<Client, Block>> + Send + Sync + 'static,
    Inner::Error: Into<ConsensusError>,
    Environment: EnvironmentT<Block> + Send + 'static,
    Environment::Proposer: Proposer<Block, Transaction = TransactionFor<Client, Block>>,
    Environment::Error: std::fmt::Debug,
    SelectChain: SelectChainT<Block> + 'static,
    SyncOracle: SyncOracleT + Send + 'static,
{
    const BLOCK_TIME_SECS: u64 = 3;

    let mut propose_block =
        move || -> Result<Proposal<Block, TransactionFor<Client, Block>>, String> {
            let best_header = select_chain
                .best_chain()
                .map_err(|err| format!("Failed to select best chain: {:?}", err))?;

            let proposer = futures::executor::block_on(environment.init(&best_header))
                .map_err(|err| format!("Failed to initialize proposer: {:?}", err))?;

            let inherent_data = Default::default();
            let inherent_digest = Default::default();
            let proposal = futures::executor::block_on(proposer.propose(
                inherent_data,
                inherent_digest,
                Duration::from_secs(BLOCK_TIME_SECS),
                RecordProof::No,
            ))
            .map_err(|err| format!("Failed proposing block: {:?}", err))?;

            Ok(proposal)
        };

    let seal_block = move |header: &mut Block::Header| {
        let seal = {
            let hash = header.hash();
            let seal = authority_key.as_ref().sign(hash.as_ref());
            DigestItem::Seal(SINGLETON_ENGINE_ID, seal.encode())
        };

        header.digest_mut().push(seal);
        let post_hash = header.hash();
        let seal = header
            .digest_mut()
            .pop()
            .expect("pushed seal above; length greater than zero; qed");

        (post_hash, seal)
    };

    let mut author_block = move || -> Result<(), String> {
        if sync_oracle.is_major_syncing() {
            debug!(target: "singleton", "Skipping proposal due to sync.");
        }

        let proposal = propose_block()?;
        let (mut header, body) = proposal.block.deconstruct();
        let (post_hash, seal) = seal_block(&mut header);

        let mut import_params = BlockImportParams::new(BlockOrigin::Own, header);
        import_params.post_digests.push(seal);
        import_params.body = Some(body);
        import_params.storage_changes = Some(proposal.storage_changes);
        import_params.post_hash = Some(post_hash);
        import_params.fork_choice = Some(ForkChoiceStrategy::LongestChain);

        inner
            .import_block(import_params, HashMap::default())
            .map_err(|err| format!("Failed to import authored block: {:?}", err))
            .map(|_| ())
    };

    thread::spawn(move || {
        loop {
            if let Err(err) = author_block() {
                warn!(target: "singleton", "Failed to author block: {:?}", err);
            }

            thread::sleep(Duration::from_secs(BLOCK_TIME_SECS));
        }
    });
}

pub async fn start_singleton_finality_gadget<Block, Backend, Client, Network>(
    config: SingletonConfig,
    authority_key: Option<SingletonFinalityAuthorityPair>,
    client: Arc<Client>,
    network: Network,
) where
    Block: BlockT,
    Backend: BackendT<Block>,
    Client: BlockchainEvents<Block> + Finalizer<Block, Backend> + Send + Sync,
    Network: GossipNetwork<Block> + Clone + Send + 'static,
{
    let topic = <<Block::Header as HeaderT>::Hashing as HashT>::hash("singleton".as_bytes());

    let gossip_engine = Arc::new(Mutex::new(GossipEngine::new(
        network,
        SINGLETON_ENGINE_ID,
        SINGLETON_PROTOCOL_NAME,
        Arc::new(AllowAll { topic }),
    )));

    let mut listener = {
        let client = client.clone();
        gossip_engine
            .lock()
            .messages_for(topic)
            .for_each(move |notification| {
                let message: SingletonFinalityMessage<Block::Hash> = match Decode::decode(
                    &mut &notification.message[..],
                ) {
                    Ok(m) => m,
                    Err(err) => {
                        warn!(target: "singleton", "Failed to decode gossip message: {:?}", err);
                        return future::ready(());
                    }
                };

                if let Some(peer) = notification.sender {
                    info!("Got finality message from: {:?}", peer);
                }

                if config
                    .finality_authority
                    .as_ref()
                    .verify(&message.block_hash, message.proof.as_ref())
                {
                    if let Err(err) = client.finalize_block(
                        BlockId::Hash(message.block_hash),
                        Some(message.proof.encode()),
                        true,
                    ) {
                        warn!(target: "singleton", "Failed finalizing block {:?}: {:?}",
                            message.block_hash,
                            err
                        );
                    }
                } else {
                    warn!(target: "singleton", "Failed verifying finality proof");
                }

                future::ready(())
            })
    };

    let finality_authority = |authority_key: SingletonFinalityAuthorityPair| {
        let gossip_engine = gossip_engine.clone();

        client
            .import_notification_stream()
            .for_each(move |notification| {
                if notification.is_new_best {
                    let proof: SingletonFinalityJustification = authority_key
                        .as_ref()
                        .sign(notification.hash.as_ref())
                        .into();

                    let proof_encoded = proof.encode();

                    // let proof_encoded = proof.encode();
                    let message = SingletonFinalityMessage {
                        block_hash: notification.hash,
                        proof,
                    };

                    gossip_engine
                        .lock()
                        .gossip_message(topic, message.encode(), true);

                    if let Err(err) = client.finalize_block(
                        BlockId::Hash(notification.hash),
                        Some(proof_encoded),
                        true,
                    ) {
                        warn!(target: "singleton", "Failed finalizing block {:?}: {:?}",
                            notification.hash,
                            err
                        );
                    }
                }

                future::ready(())
            })
    };

    let mut producer = if let Some(authority_key) = authority_key {
        finality_authority(authority_key).boxed()
    } else {
        future::pending::<()>().boxed()
    }
    .fuse();

    let mut gossip_engine = future::poll_fn(move |cx| gossip_engine.lock().poll_unpin(cx)).fuse();

    futures::select! {
        () = gossip_engine => {},
        () = listener => {},
        () = producer => {},
    }
}

#[derive(Decode, Encode)]
struct SingletonFinalityMessage<Hash> {
    block_hash: Hash,
    proof: SingletonFinalityJustification,
}

/// Allows all gossip messages to get through.
struct AllowAll<Hash> {
    topic: Hash,
}

impl<Block> GossipValidator<Block> for AllowAll<Block::Hash>
where
    Block: BlockT,
{
    fn validate(
        &self,
        _context: &mut dyn GossipValidatorContext<Block>,
        _sender: &sc_network::PeerId,
        _data: &[u8],
    ) -> GossipValidationResult<Block::Hash> {
        GossipValidationResult::ProcessAndKeep(self.topic)
    }
}
