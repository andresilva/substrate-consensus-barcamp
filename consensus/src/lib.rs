use derive_more::{AsRef, From, Into};
use std::collections::HashMap;
use std::marker::PhantomData;

use codec::{Decode, Encode};
use sp_api::{ProvideRuntimeApi, TransactionFor};
use sp_application_crypto::RuntimePublic;
use sp_consensus::{
    import_queue::{CacheKeyId, Verifier},
    BlockCheckParams, BlockImport, BlockImportParams, BlockOrigin, Error as ConsensusError,
    ForkChoiceStrategy, ImportResult,
};
use sp_core::sr25519;
use sp_runtime::{
    generic::DigestItem,
    traits::{Block as BlockT, Header as _},
    ConsensusEngineId, Justification,
};

pub const SINGLETON_ENGINE_ID: ConsensusEngineId = [b's', b'g', b't', b'n'];

#[derive(AsRef, From, Into)]
struct SingletonBlockAuthority(sr25519::Public);

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

#[derive(Debug, Display, Error)]
struct SingletonBlockImportError;
struct SingletonBlockImport<Client> {
    _client: Client,
}

impl<Block, Client> BlockImport<Block> for SingletonBlockImport<Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
{
    type Error = SingletonBlockImportError;
    type Transaction = TransactionFor<Client, Block>;

    fn check_block(
        &mut self,
        _block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        Err(SingletonBlockImportError)
    }

    fn import_block(
        &mut self,
        _block: BlockImportParams<Block, Self::Transaction>,
        _new_cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {
        Err(SingletonBlockImportError)
    }
}
