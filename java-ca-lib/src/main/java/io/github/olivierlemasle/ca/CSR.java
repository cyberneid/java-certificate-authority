package io.github.olivierlemasle.ca;

import java.io.IOException;
import java.security.PublicKey;

public interface CSR {

  public DistinguishedName getSubject();

  public PublicKey getPublicKey();
  
  public byte[] getEncoded() throws IOException;

}
