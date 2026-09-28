use crate::dispute;
use crate::RevocationData;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

fn setup() -> (Env, Address) {
    let env = Env::default();
    let contract = env.register(crate::AttestationContract, ());
    (env, contract)
}

fn in_contract<R>(env: &Env, contract: &Address, f: impl FnOnce(&Env) -> R) -> R {
    env.as_contract(contract, || f(env))
}

#[test]
fn require_not_revoked_for_update_allows_active_attestation() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-09");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            dispute::require_not_revoked_for_update(env, &business, &period);
        });
    }));

    assert!(
        result.is_ok(),
        "an active attestation must remain updatable"
    );
    assert!(!in_contract(&env, &contract, |env| {
        dispute::is_attestation_revoked(env, &business, &period)
    }));
}

#[test]
fn require_not_revoked_for_update_rejects_revoked_attestation() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let period = String::from_str(&env, "2026-09");
    let reason = String::from_str(&env, "adversarial test revocation");
    let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);

    in_contract(&env, &contract, |env| {
        dispute::record_revocation(env, &business, &period, &revocation);
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            dispute::require_not_revoked_for_update(env, &business, &period);
        });
    }));

    assert!(result.is_err(), "revoked attestations must be immutable");
    assert!(in_contract(&env, &contract, |env| {
        dispute::is_attestation_revoked(env, &business, &period)
    }));
}

#[test]
fn require_not_revoked_for_update_uses_business_and_period_boundaries() {
    let (env, contract) = setup();
    let business = Address::generate(&env);
    let other_business = Address::generate(&env);
    let period = String::from_str(&env, "");

    in_contract(&env, &contract, |env| {
        dispute::require_not_revoked_for_update(env, &business, &period);
    });

    let reason = String::from_str(&env, "only one key is revoked");
    let revocation: RevocationData = (business.clone(), env.ledger().timestamp(), reason);
    in_contract(&env, &contract, |env| {
        dispute::record_revocation(env, &business, &period, &revocation);
    });

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_contract(&env, &contract, |env| {
            dispute::require_not_revoked_for_update(env, &other_business, &period);
        });
    }));
    assert!(
        result.is_ok(),
        "revocation must be scoped to business and period"
    );
}
