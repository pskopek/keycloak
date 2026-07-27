package org.keycloak.crypto.def.test;

import org.keycloak.common.util.Environment;
import org.keycloak.crypto.MLDSASignatureTest;

import org.junit.Assume;
import org.junit.Before;

/**
 * Runs ML-DSA (CRYSTALS-Dilithium) signing tests with the default (BouncyCastle) crypto provider.
 */
public class DefaultCryptoMLDSASignatureTest extends MLDSASignatureTest {

    @Before
    public void before() {
        Assume.assumeFalse("Java is in FIPS mode. Skipping the test.", Environment.isJavaInFipsMode());
    }
}
