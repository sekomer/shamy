#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    fn test_cli_basics() {
        let output = Command::new("cargo")
            .args(["run", "--", "help"])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
    }

    #[test]
    fn test_cli_keygen() {
        let output = Command::new("cargo")
            .args([
                "run",
                "--",
                "keygen",
                "--threshold",
                "3",
                "--num-shares",
                "5",
            ])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
    }

    #[test]
    fn test_cli_combine() {
        let output = Command::new("cargo")
            .args([
                "run",
                "--",
                "schnorr",
                "combine",
                "--nonce",
                "031cb8610733456b7f163fb088a127118ddfe10689af097eb7646c96c025b8e5ae",
                "--ids",
                "0",
                "--ids",
                "1",
                "--signatures",
                "4ea64f5d0b0a68762d143eb45b6e00366923dc76d4fbc9830176b42223677016",
                "--signatures",
                "983f3626eb6cb6dddf7c9eada612b64ba7558c35db80cee908469d50b2b9441f",
            ])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
    }

    #[test]
    fn test_cli_verify() {
        let output = Command::new("cargo")
            .args([
                "run",
                "--",
                "schnorr",
                "verify",
                "--message",
                "rust is best",
                "--nonce",
                "032ab98218bf256c1e9a3d7a85f451f0879867fbc0923540c4cd2928d1f4b03303",
                "--signature",
                "2290a650e2d62d3f3155c52284d7db29cb0674ee5539be9340f816aca92c7262",
                "--public-key",
                "03dba6989ee4de1e4a4710fcd6fd7fc85970f30bb0efaa9dbd5c42f43476f95907",
            ])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
    }

    #[test]
    fn test_cli_nonce_verify() {
        let output = Command::new("cargo")
            .args([
                "run",
                "--",
                "schnorr",
                "nonce",
                "verify",
                "80dd81982ed5065cd5d8845ab5a7fa256ec1a029a5c3f85753f330d4ddc74e7b",
            ])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
    }

    #[test]
    fn test_cli_nonce_verify_invalid() {
        let output = Command::new("cargo")
            .args(["run", "--", "schnorr", "nonce", "verify", "invalid"])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
    }

    #[test]
    fn test_cli_nonce_generate() {
        let output = Command::new("cargo")
            .args(["run", "--", "schnorr", "nonce", "generate"])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
    }

    #[test]
    fn test_cli_schnorr_sign() {
        let output = Command::new("cargo")
            .args([
                "run",
                "--",
                "schnorr",
                "sign",
                "--challange",
                "cdc2e81d4d252008dbebafcf38b3cdf912fed03f3b9d2e0d656ed00dfd3965c0",
                "--share",
                "cdc2e81d4d252008dbebafcf38b3cdf912fed03f3b9d2e0d656ed00dfd3965c0",
                "--id",
                "1",
                "--nonce",
                "cf54c440ec2a5245f70c109b72816d35f6331e067fb4d26691998414dec2bc64",
            ])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
    }

    #[test]
    fn test_cli_schnorr_sign_invalid_challange() {
        let output = Command::new("cargo")
            .args([
                "run",
                "--",
                "schnorr",
                "sign",
                "--challange",
                "cdc2e81d4d252008dbebafcf38b3cdf912fed03f3b9d2e0d656ed00dfd3965",
                "--share",
                "cdc2e81d4d252008dbebafcf38b3cdf912fed03f3b9d2e0d656ed00dfd3965c0",
                "--id",
                "1",
                "--nonce",
                "cf54c440ec2a5245f70c109b72816d35f6331e067fb4d26691998414dec2bc64",
            ])
            .output()
            .expect("Failed to execute command");

        assert!(
            std::str::from_utf8(output.stderr.as_slice())
                .unwrap()
                .contains("Invalid scalar length")
        );
        assert!(!output.status.success());
    }

    #[test]
    fn test_cli_schnorr_challenge() {
        let output = Command::new("cargo")
            .args([
                "run",
                "--",
                "schnorr",
                "challenge",
                "--message",
                "rust is best",
                "--ids",
                "1",
                "2",
                "--nonces",
                "03d8bdbc558c9ab0887e5f672ac1ce97b5cef2dc9cd4a627a8860c54ab7c0589de",
                "031be5375e184e2e1053e342e9cfc862af99ed423b2860319d016993f935710012",
                "--public-key",
                "0280525d6b92596b827a51671e74a329411ac77a29e7d077be5d23b973c3fbcf59",
            ])
            .output()
            .expect("Failed to execute command");

        assert!(output.status.success());
    }
}
