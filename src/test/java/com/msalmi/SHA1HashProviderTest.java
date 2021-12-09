package com.msalmi;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordCredentialData;
import org.keycloak.models.credential.dto.PasswordSecretData;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
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

    /**
     *
     */
    @Test
    public void encodeSalt() throws UnsupportedEncodingException {
        final var provider = new SHA1HashProvider(SHA1HashProviderFactory.ID);
        var expected = "lkFXfsJ7XC0JSo+ijMIagIHvuL8=";

        String salt = "OirIPM4rKE79IWL2lTclog==";
        String saltBase64Dr = new String(Base64.getDecoder().decode(salt), "UTF-16LE");
        System.out.println("salt = " + saltBase64Dr);
        String pass = "123456";
        var encodedBase64 = provider.encode(saltBase64Dr+pass, 0);
        System.out.println("hashed = " + encodedBase64);

        assertTrue(encodedBase64.equals(expected));

    }

    @Test
    public void encodeSalt2() throws IOException {
        PasswordSecretData passwordSecretData = new PasswordSecretData( "lkFXfsJ7XC0JSo+ijMIagIHvuL8=","OirIPM4rKE79IWL2lTclog==");
        PasswordCredentialModel credentialModel = PasswordCredentialModel.createFromValues("sha1-salted", passwordSecretData.getSalt(), 0, passwordSecretData.getValue());
        final var provider = new SHA1HashProvider(SHA1HashProviderFactory.ID);
        assertTrue(provider.verify("123456", credentialModel));

    }
}
