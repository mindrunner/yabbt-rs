pub mod bw_live;
pub mod e2e_seed;
pub mod vaultwarden;

pub type E2eResult<T> = Result<T, Box<dyn std::error::Error>>;

pub fn live_e2e_enabled() -> bool {
    matches!(
        std::env::var("YABBT_E2E_VAULTWARDEN").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}
