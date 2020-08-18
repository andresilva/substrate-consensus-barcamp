use derive_more::{Display, Error};
use std::collections::HashMap;

use sp_api::{ProvideRuntimeApi, TransactionFor};
use sp_consensus::{
    import_queue::{CacheKeyId, Verifier},
    BlockCheckParams, BlockImport, BlockImportParams, BlockOrigin, ImportResult,
};
use sp_runtime::{traits::Block as BlockT, Justification};

struct SingletonVerifier;

impl<Block> Verifier<Block> for SingletonVerifier
where
    Block: BlockT,
{
    fn verify(
        &mut self,
        _origin: BlockOrigin,
        _header: Block::Header,
        _justification: Option<Justification>,
        _body: Option<Vec<Block::Extrinsic>>,
    ) -> Result<
        (
            BlockImportParams<Block, ()>,
            Option<Vec<(CacheKeyId, Vec<u8>)>>,
        ),
        String,
    > {
        Err("unimplemented".into())
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
