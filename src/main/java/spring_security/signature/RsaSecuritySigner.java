package spring_security.signature;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.core.userdetails.UserDetails;

public class RsaSecuritySigner extends SecuritySigner{

    @Override
    public String getToken(UserDetails user, JWK jwk) throws JOSEException {
        RSASSASigner jwsSigner = new RSASSASigner(((RSAKey) jwk).toPrivateKey());

        return super.getJwtTokenInternal(jwsSigner, user, jwk);
    }
}
