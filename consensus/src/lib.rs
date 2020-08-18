use derive_more::{Display, Error};
use std::collections::HashMap;
use std::marker::PhantomData;

use sp_api::{ProvideRuntimeApi, TransactionFor};
use sp_consensus::{
    import_queue::{CacheKeyId, Verifier},
    BlockCheckParams, BlockImport, BlockImportParams, BlockOrigin, ForkChoiceStrategy,
    ImportResult,
};
use sp_runtime::{traits::Block as BlockT, Justification};

#[derive(Default)]
struct SingletonVerifier<Block>(PhantomData<Block>);

impl<Block> SingletonVerifier<Block>
where
    Block: BlockT,
{
    fn check_header(&self, _header: &Block::Header) -> Result<(), String> {
        // Perform any cheap checks that don't require the parent header to
        // already be imported. E.g. make sure that the header contains a seal
        // digest.
        Ok(())
    }
}

impl<Block> Verifier<Block> for SingletonVerifier<Block>
where
    Block: BlockT,
{
    fn verify(
        &mut self,
        origin: BlockOrigin,
        header: Block::Header,
        justification: Option<Justification>,
        body: Option<Vec<Block::Extrinsic>>,
    ) -> Result<
        (
            BlockImportParams<Block, ()>,
            Option<Vec<(CacheKeyId, Vec<u8>)>>,
        ),
        String,
    > {
        self.check_header(&header)?;

        let mut import_params = BlockImportParams::new(origin, header);

        import_params.justification = justification;
        import_params.body = body;
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
