package io.github.olivierlemasle.ca.ext;

import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

/**
 * CRL Distribution Points
 */
public class AuthorityKeyIdentifierExtension extends CertExtension {

	
	AuthorityKeyIdentifierExtension(AuthorityKeyIdentifier  authorityKeyIdentifier) {
				
		super(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
  }

  /**
   * Creates a {@link AuthorityKeyIdentifierExtension} with only a {@code ocspEndPointUrl} URI (no {@code reasons}
 * @throws OperatorCreationException 
   */
  public static AuthorityKeyIdentifierExtension create(final X509CertificateHolder cert) throws OperatorCreationException
  {		  
	// Create a DigestCalculator
	  DigestCalculator digestCalculator = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

	  X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digestCalculator);
	  AuthorityKeyIdentifier authorityKeyIdentifier = x509ExtensionUtils.createAuthorityKeyIdentifier(cert);
	  	 	  
	  return new AuthorityKeyIdentifierExtension(authorityKeyIdentifier);
  }
}
