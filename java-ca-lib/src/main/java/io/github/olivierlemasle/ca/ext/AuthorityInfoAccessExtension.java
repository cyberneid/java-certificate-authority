package io.github.olivierlemasle.ca.ext;

import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * CRL Distribution Points
 */
public class AuthorityInfoAccessExtension extends CertExtension {

	
	AuthorityInfoAccessExtension(AuthorityInformationAccess authorityInfoAccess) {
				
		super(Extension.authorityInfoAccess, false, authorityInfoAccess);
  }

  /**
   * Creates a {@link AuthorityInfoAccessExtension} with only a {@code ocspEndPointUrl} URI (no {@code reasons}
   */
  public static AuthorityInfoAccessExtension create(final String ocspEndPointUrl)
  {	
		// Create an AuthorityInfoAccess extension with an OCSP URL
		AuthorityInformationAccess authorityInfoAccess = new AuthorityInformationAccess(
		    AccessDescription.id_ad_ocsp,
		    new GeneralName(GeneralName.uniformResourceIdentifier,
		        new DERIA5String(ocspEndPointUrl)));
		
		return new AuthorityInfoAccessExtension(authorityInfoAccess);
  }
}
