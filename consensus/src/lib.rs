use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;

use codec::{Decode, Encode};
use derive_more::{AsRef, From, Into};
use futures::{
    future::{self, FutureExt},
    stream::{self, StreamExt},
};
use futures_timer::Delay;
use log::{debug, warn};

use sp_api::{ProvideRuntimeApi, TransactionFor};
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
    traits::{Block as BlockT, Header as _},
    ConsensusEngineId, Justification,
};

pub const SINGLETON_ENGINE_ID: ConsensusEngineId = [b's', b'g', b't', b'n'];

#[derive(AsRef, From, Into)]
pub struct SingletonBlockAuthority(sr25519::Public);

#[derive(AsRef, From, Into)]
pub struct SingletonBlockAuthorityPair(sr25519::Pair);

#[derive(AsRef, Encode, Decode, From)]
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

struct SingletonBlockImport<Client> {
    client: Client,
}

impl<Block, Client> BlockImport<Block> for SingletonBlockImport<Client>
where
    Block: BlockT,
    Client:
        BlockImport<Block, Transaction = TransactionFor<Client, Block>> + ProvideRuntimeApi<Block>,
    Client::Error: Into<ConsensusError>,
{
    type Error = ConsensusError;
    type Transaction = TransactionFor<Client, Block>;

    fn check_block(&mut self, block: BlockCheckParams<Block>) -> Result<ImportResult, Self::Error> {
        self.client.check_block(block).map_err(Into::into)
    }

    fn import_block(
        &mut self,
        block: BlockImportParams<Block, Self::Transaction>,
        new_cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {
        self.client
            .import_block(block, new_cache)
            .map_err(Into::into)
    }
}

pub struct SingletonConfig {
    pub block_authority: SingletonBlockAuthority,
}

pub fn import_queue<Block, Client>(
    config: SingletonConfig,
    client: Client,
    spawner: &impl sp_core::traits::SpawnNamed,
) -> BasicQueue<Block, TransactionFor<Client, Block>>
where
    Block: BlockT,
    Client: BlockImport<Block, Transaction = TransactionFor<Client, Block>>
        + ProvideRuntimeApi<Block>
        + Clone
        + Send
        + Sync
        + 'static,
    Client::Error: Into<ConsensusError>,
{
    let block_import = Box::new(SingletonBlockImport {
        client: client.clone(),
    });

    let verifier = SingletonVerifier {
        authority: config.block_authority,
        _phantom: PhantomData,
    };

    BasicQueue::new(verifier, block_import, None, None, spawner, None)
}

pub fn start_singleton_block_author<Block, Client, Environment, SelectChain, SyncOracle>(
    _config: SingletonConfig,
    authority_key: SingletonBlockAuthorityPair,
    mut client: Client,
    mut environment: Environment,
    select_chain: SelectChain,
    mut sync_oracle: SyncOracle,
) -> impl Future<Output = ()>
where
    Block: BlockT,
    Client: BlockImport<Block, Transaction = TransactionFor<Client, Block>>
        + ProvideRuntimeApi<Block>
        + 'static,
    Environment: EnvironmentT<Block>,
    Environment::Proposer: Proposer<Block, Transaction = TransactionFor<Client, Block>>,
    Environment::Error: std::fmt::Debug,
    SelectChain: SelectChainT<Block> + 'static,
    SyncOracle: SyncOracleT + 'static,
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

        client
            .import_block(import_params, HashMap::default())
            .map_err(|err| format!("Failed to import authored block: {:?}", err))
            .map(|_| ())
    };

    let interval_stream = stream::unfold((), |()| {
        Delay::new(Duration::from_secs(BLOCK_TIME_SECS)).map(|_| Some(((), ())))
    });

    interval_stream.fold((), move |(), ()| {
        if let Err(err) = author_block() {
            warn!(target: "singleton", "Failed to author block: {:?}", err);
        }
        future::ready(())
    })
}
