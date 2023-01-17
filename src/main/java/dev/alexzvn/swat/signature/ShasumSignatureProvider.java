package dev.alexzvn.swat.signature;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ShasumSignatureProvider extends SignatureProvider {
    private final Mac mac;

    public ShasumSignatureProvider(String secret, String algo) throws NoSuchAlgorithmException, InvalidKeyException {
        super(secret);

        mac = Mac.getInstance(algo);
        mac.init(new SecretKeySpec(secret.getBytes(), algo));
    }

    public String sign(String data) {
        return Base64.getEncoder().encodeToString(
            mac.doFinal(data.getBytes())
        );
    }

    public boolean verify(String data, String signature) {
        if (signature == null) {
            return false;
        }

        byte[] computedSignature = mac.doFinal(data.getBytes());
        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        if (computedSignature.length != signatureBytes.length) {
            return false;
        }

        return MessageDigest.isEqual(computedSignature, signatureBytes);
    }
}

