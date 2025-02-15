package io.github.olivierlemasle.ca;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

class CsrImpl implements CSR {
  private final DistinguishedName dn;
  private final PublicKey publicKey;
  private PKCS10CertificationRequest request;
  
  public CsrImpl(final PKCS10CertificationRequest request) {
    this.request = request;
    
	dn = new BcX500NameDnImpl(request.getSubject());
    try {
      publicKey = new JcaPEMKeyConverter().getPublicKey(request.getSubjectPublicKeyInfo());
    } catch (final PEMException e) {
      throw new CaException(e);
    }
  }

  @Override
  public DistinguishedName getSubject() {
    return dn;
  }

  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public byte[] getEncoded() throws IOException {
    return request.getEncoded();
  }
}
