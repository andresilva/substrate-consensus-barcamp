//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use node_template_runtime::{self, opaque::Block, RuntimeApi};
use sc_client_api::RemoteBackend;
use sc_executor::native_executor_instance;
pub use sc_executor::NativeExecutor;
use sc_service::{error::Error as ServiceError, Configuration, ServiceComponents, TaskManager};
use std::sync::Arc;

// Our native executor instance.
native_executor_instance!(
    pub Executor,
    node_template_runtime::api::dispatch,
    node_template_runtime::native_version,
);

type FullClient = sc_service::TFullClient<Block, RuntimeApi, Executor>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

pub fn new_full_params(
    config: Configuration,
) -> Result<
    (
        sc_service::ServiceParams<
            Block,
            FullClient,
            consensus::SingletonImportQueue<Block, FullClient>,
            sc_transaction_pool::FullPool<Block, FullClient>,
            (),
            FullBackend,
        >,
        consensus::SingletonConfig,
        FullSelectChain,
    ),
    ServiceError,
> {
    let (client, backend, keystore, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, Executor>(&config)?;
    let client = Arc::new(client);

    let select_chain = sc_consensus::LongestChain::new(backend.clone());

    let pool_api =
        sc_transaction_pool::FullChainApi::new(client.clone(), config.prometheus_registry());
    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        std::sync::Arc::new(pool_api),
        config.prometheus_registry(),
        task_manager.spawn_handle(),
        client.clone(),
    );

    let singleton_config = consensus::SingletonConfig {
        block_authority: sp_keyring::sr25519::Keyring::Alice.public().into(),
        finality_authority: sp_keyring::sr25519::Keyring::Bob.public().into(),
    };

    let import_queue = consensus::import_queue(
        singleton_config.clone(),
        client.clone(),
        client.clone(),
        &task_manager.spawn_handle(),
    );

    let params = sc_service::ServiceParams {
        backend,
        client,
        import_queue,
        keystore,
        task_manager,
        transaction_pool,
        config,
        block_announce_validator_builder: None,
        finality_proof_request_builder: None,
        finality_proof_provider: None,
        on_demand: None,
        remote_blockchain: None,
        rpc_extensions_builder: Box::new(|_| ()),
    };

    Ok((params, singleton_config, select_chain))
}

/// Builds a new service for a full client.
pub fn new_full(
    config: Configuration,
    finality_gadget: bool,
    finality_gadget_validator: bool,
) -> Result<TaskManager, ServiceError> {
    let (params, singleton_config, select_chain) = new_full_params(config)?;

    let (role, prometheus_registry, client, transaction_pool) = {
        let sc_service::ServiceParams {
            config,
            client,
            transaction_pool,
            ..
        } = &params;

        (
            config.role.clone(),
            config.prometheus_registry().cloned(),
            client.clone(),
            transaction_pool.clone(),
        )
    };

    let ServiceComponents {
        task_manager,
        network,
        ..
    } = sc_service::build(params)?;

    if role.is_authority() {
        let proposer = sc_basic_authorship::ProposerFactory::new(
            client.clone(),
            transaction_pool,
            prometheus_registry.as_ref(),
        );

        consensus::start_singleton_block_author(
            sp_keyring::sr25519::Keyring::Alice.pair().into(),
            client.clone(),
            client.clone(),
            proposer,
            select_chain,
            network.clone(),
        );
    }

    let finality_gadget_authority_key = if finality_gadget_validator {
        Some(sp_keyring::sr25519::Keyring::Bob.pair().into())
    } else {
        None
    };

    if finality_gadget {
        task_manager.spawn_essential_handle().spawn_blocking(
            "singleton-finality-gadget",
            consensus::start_singleton_finality_gadget(
                singleton_config,
                finality_gadget_authority_key,
                client.clone(),
                network.clone(),
            ),
        );
    }

    Ok(task_manager)
}

/// Builds a new service for a light client.
pub fn new_light(config: Configuration) -> Result<TaskManager, ServiceError> {
    let (client, backend, keystore, task_manager, on_demand) =
        sc_service::new_light_parts::<Block, RuntimeApi, Executor>(&config)?;

    let transaction_pool_api = Arc::new(sc_transaction_pool::LightChainApi::new(
        client.clone(),
        on_demand.clone(),
    ));
    let transaction_pool = sc_transaction_pool::BasicPool::new_light(
        config.transaction_pool.clone(),
        transaction_pool_api,
        config.prometheus_registry(),
        task_manager.spawn_handle(),
    );

    let singleton_config = consensus::SingletonConfig {
        block_authority: sp_keyring::sr25519::Keyring::Alice.public().into(),
        finality_authority: sp_keyring::sr25519::Keyring::Bob.public().into(),
    };

    let import_queue = consensus::import_queue(
        singleton_config,
        client.clone(),
        client.clone(),
        &task_manager.spawn_handle(),
    );

    sc_service::build(sc_service::ServiceParams {
        block_announce_validator_builder: None,
        finality_proof_request_builder: None,
        finality_proof_provider: None,
        on_demand: Some(on_demand),
        remote_blockchain: Some(backend.remote_blockchain()),
        rpc_extensions_builder: Box::new(|_| ()),
        transaction_pool: Arc::new(transaction_pool),
        config,
        client,
        import_queue,
        keystore,
        backend,
        task_manager,
    })
    .map(|ServiceComponents { task_manager, .. }| task_manager)
}
