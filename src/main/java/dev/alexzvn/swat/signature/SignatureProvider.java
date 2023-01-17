package dev.alexzvn.swat.signature;

abstract public class SignatureProvider {
    protected String secret;

    public SignatureProvider(String secret) {
        this.secret = secret;
    }

    abstract public String sign(String data);
    abstract public boolean verify(String data, String signature);
}
