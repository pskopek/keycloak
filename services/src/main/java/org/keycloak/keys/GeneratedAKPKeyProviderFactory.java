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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import org.jboss.logging.Logger;

import static org.keycloak.provider.ProviderConfigProperty.LIST_TYPE;

/**
 * Factory for generated AKP (Asymmetric Key Pair) key providers supporting
 * PQC algorithms ML-DSA-44, ML-DSA-65, and ML-DSA-87 (CRYSTALS-Dilithium).
 */
public class GeneratedAKPKeyProviderFactory implements KeyProviderFactory {

    private static final Logger logger = Logger.getLogger(GeneratedAKPKeyProviderFactory.class);

    public static final String ID = "akp-generated";

    static final String AKP_PRIVATE_KEY_CONFIG = "akpPrivateKey";
    static final String AKP_PUBLIC_KEY_CONFIG = "akpPublicKey";
    static final String AKP_ALGORITHM_CONFIG = "akpAlgorithm";

    public static final String DEFAULT_AKP_ALGORITHM = Algorithm.ML_DSA_65;

    private static final ProviderConfigProperty AKP_ALGORITHM_PROPERTY = new ProviderConfigProperty(
            AKP_ALGORITHM_CONFIG, "ML-DSA Algorithm",
            "ML-DSA security level: ML-DSA-44 (level 2), ML-DSA-65 (level 3), ML-DSA-87 (level 5)",
            LIST_TYPE, DEFAULT_AKP_ALGORITHM,
            Algorithm.ML_DSA_44, Algorithm.ML_DSA_65, Algorithm.ML_DSA_87);

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property(Attributes.PRIORITY_PROPERTY)
            .property(Attributes.ENABLED_PROPERTY)
            .property(Attributes.ACTIVE_PROPERTY)
            .property(AKP_ALGORITHM_PROPERTY)
            .build();

    @Override
    public KeyProvider create(KeycloakSession session, ComponentModel model) {
        return new GeneratedAKPKeyProvider(session.getContext().getRealm(), model);
    }

    @Override
    public boolean createFallbackKeys(KeycloakSession session, KeyUse keyUse, String algorithm) {
        if (keyUse.equals(KeyUse.SIG) && isMlDsaAlgorithm(algorithm)) {
            RealmModel realm = session.getContext().getRealm();

            ComponentModel generated = new ComponentModel();
            generated.setName("fallback-" + algorithm);
            generated.setParentId(realm.getId());
            generated.setProviderId(ID);
            generated.setProviderType(KeyProvider.class.getName());

            MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
            config.putSingle(Attributes.PRIORITY_KEY, "-100");
            config.putSingle(AKP_ALGORITHM_CONFIG, algorithm);
            generated.setConfig(config);

            realm.addComponentModel(generated);
            return true;
        }
        return false;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
            throws ComponentValidationException {
        ConfigurationValidationHelper.check(model)
                .checkLong(Attributes.PRIORITY_PROPERTY, false)
                .checkBoolean(Attributes.ENABLED_PROPERTY, false)
                .checkBoolean(Attributes.ACTIVE_PROPERTY, false);

        String algorithm = model.get(AKP_ALGORITHM_CONFIG);
        if (algorithm == null) {
            algorithm = DEFAULT_AKP_ALGORITHM;
        }

        if (!(model.contains(AKP_PRIVATE_KEY_CONFIG) && model.contains(AKP_PUBLIC_KEY_CONFIG))) {
            generateKeys(model, algorithm);
            logger.debugv("Generated AKP keys for realm {0} using algorithm {1}", realm.getName(), algorithm);
        } else {
            // Regenerate if algorithm changed
            String storedAlgorithm = model.get(AKP_ALGORITHM_CONFIG);
            if (!algorithm.equals(storedAlgorithm)) {
                generateKeys(model, algorithm);
                logger.debugv("AKP algorithm changed, regenerating keys for realm {0}", realm.getName());
            }
        }
    }

    private void generateKeys(ComponentModel model, String algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            KeyPair keyPair = generator.generateKeyPair();
            model.put(AKP_PRIVATE_KEY_CONFIG, java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            model.put(AKP_PUBLIC_KEY_CONFIG, java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            model.put(AKP_ALGORITHM_CONFIG, algorithm);
        } catch (Exception e) {
            throw new ComponentValidationException("Failed to generate AKP keys for algorithm " + algorithm, e);
        }
    }

    private static boolean isMlDsaAlgorithm(String algorithm) {
        return Algorithm.ML_DSA_44.equals(algorithm)
                || Algorithm.ML_DSA_65.equals(algorithm)
                || Algorithm.ML_DSA_87.equals(algorithm);
    }

    @Override
    public String getHelpText() {
        return "Generates ML-DSA (CRYSTALS-Dilithium) post-quantum cryptography keys";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getId() {
        return ID;
    }
}
