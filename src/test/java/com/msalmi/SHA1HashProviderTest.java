package com.msalmi;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordCredentialData;
import org.keycloak.models.credential.dto.PasswordSecretData;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SHA1HashProviderTest {

	@Test
	public void encodeHelloWorld() {
		final var provider = new SHA1HashProvider(SHA1HashProviderFactory.ID);
		var expected = "Kq5sNclPz7QV2+lfQIuc6R7oRu0=";
		var encoded = provider.encode("hello world", 0);
		assertTrue(encoded.equals(expected));
	}

	@Test
	public void encodeEmptyString() {
		final var provider = new SHA1HashProvider(SHA1HashProviderFactory.ID);
		var expected = "2jmj7l5rSw0yVb/vlWAYkK/YBwk=";
		var encoded = provider.encode("", 0);
		assertTrue(encoded.equals(expected));
	}

	@Test
	public void ensureIterationParameterIsIgnored() {
		final var provider = new SHA1HashProvider(SHA1HashProviderFactory.ID);
		var expected = "2jmj7l5rSw0yVb/vlWAYkK/YBwk=";
		var encoded = provider.encode("", 0);
		assertTrue(encoded.equals(expected));

		expected = "2jmj7l5rSw0yVb/vlWAYkK/YBwk=";
		encoded = provider.encode("", 42); // any random number
		assertTrue(encoded.equals(expected));
	}

	@Test
	public void testHashesWithLeadingZeros() {
		final var provider = new SHA1HashProvider(SHA1HashProviderFactory.ID);
		var expected = "BC3EUS+j05HFFwzzqmHmpjj4Q0I=";
		var encoded = provider.encode("i", 0);
		assertTrue(encoded.equals(expected));
	}

    @Test
    public void encodeSalt() {
        final var provider = new SHA1HashProvider(SHA1HashProviderFactory.ID);
        var expected = "9mcmOmNw5lbi+FStSQr3hy5/S/s=";
        String salt = "salt";
        String saltBase64 = Base64.getEncoder().encodeToString(salt.getBytes(StandardCharsets.UTF_8));
        System.out.println("salt = " + saltBase64);
        String pass = "user";
        var encodedBase64 = provider.encode(salt+pass, 0);
        System.out.println("hashed = " + encodedBase64);
        assertTrue(encodedBase64.equals(expected));

    }
    @Test
    public void verify() throws IOException {
        final var provider = new SHA1HashProvider(SHA1HashProviderFactory.ID);
        String salt = "xk2kekAFrJEqrGm5jqld2Q==";
        String encodedPass = "14R4YMIzQz4ZfdOEUOALMxnM1aw=";
//        PasswordCredentialData cred = new PasswordCredentialData(1, "sha-salted");
//        PasswordSecretData se = new PasswordSecretData("14R4YMIzQz4ZfdOEUOALMxnM1aw=", "xk2kekAFrJEqrGm5jqld2Q==");
        PasswordCredentialModel var2 =  PasswordCredentialModel.createFromValues("sha-salted", salt.getBytes(StandardCharsets.UTF_8), 1, encodedPass);
        provider.verify("thuan@123",var2 );
    }

}
