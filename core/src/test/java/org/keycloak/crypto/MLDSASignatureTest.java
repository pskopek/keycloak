package org.keycloak.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import org.keycloak.rule.CryptoInitRule;

import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

/**
 * Tests ML-DSA (CRYSTALS-Dilithium) signing and verification for all three security levels.
 */
public abstract class MLDSASignatureTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Test
    public void testSignAndVerifyMLDSA44() throws Exception {
        testSignAndVerify(Algorithm.ML_DSA_44);
    }

    @Test
    public void testSignAndVerifyMLDSA65() throws Exception {
        testSignAndVerify(Algorithm.ML_DSA_65);
    }

    @Test
    public void testSignAndVerifyMLDSA87() throws Exception {
        testSignAndVerify(Algorithm.ML_DSA_87);
    }

    @Test
    public void testWrongKeyFailsVerificationMLDSA44() throws Exception {
        testWrongKeyFailsVerification(Algorithm.ML_DSA_44);
    }

    @Test
    public void testWrongKeyFailsVerificationMLDSA65() throws Exception {
        testWrongKeyFailsVerification(Algorithm.ML_DSA_65);
    }

    @Test
    public void testWrongKeyFailsVerificationMLDSA87() throws Exception {
        testWrongKeyFailsVerification(Algorithm.ML_DSA_87);
    }

    @Test
    public void testJavaAlgorithmMapping() {
        Assert.assertEquals(Algorithm.ML_DSA_44, JavaAlgorithm.getJavaAlgorithm(Algorithm.ML_DSA_44));
        Assert.assertEquals(Algorithm.ML_DSA_65, JavaAlgorithm.getJavaAlgorithm(Algorithm.ML_DSA_65));
        Assert.assertEquals(Algorithm.ML_DSA_87, JavaAlgorithm.getJavaAlgorithm(Algorithm.ML_DSA_87));
        Assert.assertEquals(KeyType.AKP, JavaAlgorithm.getKeyType(Algorithm.ML_DSA_44));
        Assert.assertEquals(KeyType.AKP, JavaAlgorithm.getKeyType(Algorithm.ML_DSA_65));
        Assert.assertEquals(KeyType.AKP, JavaAlgorithm.getKeyType(Algorithm.ML_DSA_87));
    }

    private void testSignAndVerify(String algorithm) throws Exception {
        byte[] data = "Hello, post-quantum world!".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        KeyPair keyPair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] sig = signer.sign();

        Assert.assertNotNull("Signature must not be null", sig);
        Assert.assertTrue("Signature must not be empty", sig.length > 0);

        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        Assert.assertTrue("Signature must verify successfully", verifier.verify(sig));
    }

    private void testWrongKeyFailsVerification(String algorithm) throws Exception {
        byte[] data = "Hello, post-quantum world!".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        KeyPair signingPair = kpg.generateKeyPair();
        KeyPair otherPair = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(signingPair.getPrivate());
        signer.update(data);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(otherPair.getPublic());
        verifier.update(data);
        Assert.assertFalse("Verification with wrong key must fail", verifier.verify(sig));
    }
}
