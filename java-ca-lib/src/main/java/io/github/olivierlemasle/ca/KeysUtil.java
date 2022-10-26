package io.github.olivierlemasle.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

final class KeysUtil {
  private static final String ALGORITHM = "RSA";
  private static final int DEFAULT_KEY_SIZE = 2048;

  private KeysUtil() {
  }

  static KeyPair generateKeyPair() {
    return generateKeyPair(DEFAULT_KEY_SIZE);
  }

  static KeyPair generateKeyPair(final int keySize) {
    try {
      final KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGORITHM);
      gen.initialize(keySize);
      return gen.generateKeyPair();
    } catch (final NoSuchAlgorithmException | InvalidParameterException e) {
      throw new CaException(e);
    }
  }
  
  static KeyPair generateKeyPair(final int keySize, Provider provider) {
	    try {
	    		        
	    	final KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGORITHM, provider);
	    	gen.initialize(keySize);
	    	
	    	return gen.generateKeyPair();
	    } 
	    catch (final Exception e) {
	      throw new CaException(e);
	    }
  }
}
