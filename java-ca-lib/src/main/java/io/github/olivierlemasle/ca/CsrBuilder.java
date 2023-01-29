package io.github.olivierlemasle.ca;

import java.security.Provider;

public interface CsrBuilder {

  public CsrWithPrivateKey generateRequest(DistinguishedName name, Provider p);

}
