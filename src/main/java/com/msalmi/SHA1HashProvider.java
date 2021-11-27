package com.msalmi;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

public class SHA1HashProvider implements PasswordHashProvider {

	private final String providerId;
	public static final String ALGORITHM = "SHA-1";

	public SHA1HashProvider(String providerId) {
		this.providerId = providerId;
	}

	@Override
	public void close() {
	}

	@Override
	public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
		return this.providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
	}

	@Override
	public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
		String encodedPassword = this.encode(rawPassword, iterations);
		return PasswordCredentialModel.createFromValues(this.providerId, new byte[0], iterations, encodedPassword);
	}

	@Override
	public boolean verify(String rawPassword, PasswordCredentialModel credential) {
		String salt = new String(credential.getPasswordSecretData().getSalt(), StandardCharsets.UTF_8);
        String hash = credential.getPasswordSecretData().getValue();
        String encodedPassword = this.encode(salt + rawPassword, credential.getPasswordCredentialData().getHashIterations());

        //Option2:
        byte[] one = credential.getPasswordSecretData().getSalt();
        byte[] two = rawPassword.getBytes();
        byte[] combined = new byte[one.length + two.length];
        System.arraycopy(one,0,combined,0         ,one.length);
        System.arraycopy(two,0,combined,one.length,two.length);
        String combinedPass = new String(combined, StandardCharsets.UTF_8);

        String encodedPasswordFromByte = this.encode(combinedPass, credential.getPasswordCredentialData().getHashIterations());

        return Arrays.asList(encodedPassword, encodedPasswordFromByte)
            .stream().anyMatch(s -> {
               return s.equals(hash);
            });
	}

	@Override
	public String encode(String rawPassword, int iterations) {
		try {
			MessageDigest md = MessageDigest.getInstance(ALGORITHM);
			md.update(rawPassword.getBytes());
            byte[] hashed = md.digest();

            return Base64.getEncoder().encodeToString(hashed);
		} catch (Exception e) {
			// fail silently
		}

		return null;
	}

}
