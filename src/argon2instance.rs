use argon2::{Algorithm, Argon2, Params, Version};

const ARGON2_MEMORY_COST: u32 = Params::DEFAULT_M_COST;
const ARGON2_TIME_COST: u32 = Params::DEFAULT_T_COST;
const ARGON2_PARALLELISM: u32 = Params::DEFAULT_P_COST;

pub fn argon2_instance() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            ARGON2_MEMORY_COST,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            None,
        )
        .expect("Invalid Argon2 parameters"),
    )
}
