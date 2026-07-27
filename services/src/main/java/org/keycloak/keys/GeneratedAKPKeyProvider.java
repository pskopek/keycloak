/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.keys;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.RealmModel;

import org.jboss.logging.Logger;

/**
 * Key provider for generated AKP (Asymmetric Key Pair) keys used for PQC algorithms
 * such as ML-DSA (CRYSTALS-Dilithium). Keys are generated and stored in the component model.
 */
public class GeneratedAKPKeyProvider extends AbstractAKPKeyProvider {

    private static final Logger logger = Logger.getLogger(GeneratedAKPKeyProvider.class);

    public GeneratedAKPKeyProvider(RealmModel realm, ComponentModel model) {
        super(realm, model);
    }

    @Override
    protected KeyWrapper loadKey(RealmModel realm, ComponentModel model) {
        String privateKeyBase64 = model.getConfig().getFirst(GeneratedAKPKeyProviderFactory.AKP_PRIVATE_KEY_CONFIG);
        String publicKeyBase64 = model.getConfig().getFirst(GeneratedAKPKeyProviderFactory.AKP_PUBLIC_KEY_CONFIG);
        String algorithm = model.getConfig().getFirst(GeneratedAKPKeyProviderFactory.AKP_ALGORITHM_CONFIG);

        try {
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(privateKeyBase64));
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            PrivateKey privateKey = kf.generatePrivate(privateKeySpec);

            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(publicKeyBase64));
            PublicKey publicKey = kf.generatePublic(publicKeySpec);

            KeyPair keyPair = new KeyPair(publicKey, privateKey);
            return createKeyWrapper(keyPair, algorithm);
        } catch (Exception e) {
            logger.warnf("Failed to load AKP key for algorithm %s: %s", algorithm, e.toString());
            return null;
        }
    }
}
