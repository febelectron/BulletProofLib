package edu.stanford.cs.crypto.efficientct.circuit.groups;

import org.bouncycastle.math.ec.ECPoint;

import java.io.*;
import java.math.BigInteger;

public class BouncyCastleECPoint implements GroupElement<BouncyCastleECPoint>, Externalizable {
    public static int expCount=0;
    public static int addCount=0;

    private ECPoint point;

    public BouncyCastleECPoint() {
    }

    public BouncyCastleECPoint(ObjectInput in) throws IOException {
        readExternal(in);
    }

    public BouncyCastleECPoint(ECPoint point) {
        this.point = point;
    }

    @Override
    public BouncyCastleECPoint add(BouncyCastleECPoint other) {
        ++addCount;
        return from(point.add(other.point));
    }

    @Override
    public BouncyCastleECPoint multiply(BigInteger exp) {
        ++expCount;
        return from(point.multiply(exp));
    }

    @Override
    public BouncyCastleECPoint negate() {
        return from(point.negate());
    }

    @Override
    public byte[] canonicalRepresentation() {
        return point.getEncoded(true);
    }

    @Override
    public String stringRepresentation() {
        return point.normalize().toString();
    }

    private static  BouncyCastleECPoint from(ECPoint point) {
        return new BouncyCastleECPoint(point);
    }

    public ECPoint getPoint() {
        return point;
    }

    @Override
    public String toString() {
        return point.normalize().toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        BouncyCastleECPoint that = (BouncyCastleECPoint) o;

        return point != null ? point.equals(that.point) : that.point == null;
    }

    @Override
    public int hashCode() {
        return point != null ? point.hashCode() : 0;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.write(point.getEncoded(true));
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException {
        BouncyCastleCurve curve = Secp256k1.INSTANCE;
        byte[] b = new byte[33]; //todo: check if it always?
        in.read(b);
        this.point = curve.getCurve().decodePoint(b);
    }
}
