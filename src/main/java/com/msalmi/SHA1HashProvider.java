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
        System.out.println("Raw salt:" + credential.getPasswordSecretData().getSalt());
		String salt = new String(credential.getPasswordSecretData().getSalt(), StandardCharsets.UTF_8);
        String saltbase64 = Base64.getEncoder().encodeToString(credential.getPasswordSecretData().getSalt());
        System.out.println("Raw pass:" +  rawPassword +",  Raw Salt:" + salt + " Salt64: " + saltbase64);

        String hash = credential.getPasswordSecretData().getValue();
        String decodedSalt = new String(Base64.getDecoder().decode(credential.getPasswordSecretData().getSalt()));
        System.out.println("Decoded:" + decodedSalt);
        String encodedPassword = this.encode(  decodedSalt + rawPassword, credential.getPasswordCredentialData().getHashIterations());

        //Option3:
        byte[] one = Base64.getDecoder().decode(saltbase64);
        byte[] two = rawPassword.getBytes();
        byte[] combined = new byte[one.length + two.length];
        System.arraycopy(one,0,combined,0         ,one.length);
        System.arraycopy(two,0,combined,one.length,two.length);
        String combinedPass = new String(combined, StandardCharsets.UTF_8);
        System.out.println("combinedPass: "+ combinedPass);
        String encodedPasswordFromByte = this.encode(combinedPass, credential.getPasswordCredentialData().getHashIterations());

        return Arrays.asList(encodedPassword, encodedPasswordFromByte)
            .stream().anyMatch(s -> {
                System.out.println("encoded: "+ s +", vs currentHash: " + hash);
               return s.equals(hash);
            });
	}

	@Override
	public String encode(String rawPassword, int iterations) {
		try {
			MessageDigest md = MessageDigest.getInstance(ALGORITHM);
			md.update(rawPassword.getBytes(StandardCharsets.UTF_8));
            byte[] hashed = md.digest();

            return Base64.getEncoder().encodeToString(hashed);
		} catch (Exception e) {
			// fail silently
		}

		return null;
	}

}
