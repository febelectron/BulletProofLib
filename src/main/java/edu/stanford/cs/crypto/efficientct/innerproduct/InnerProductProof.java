package edu.stanford.cs.crypto.efficientct.innerproduct;

import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Created by buenz on 6/28/17.
 */
public class InnerProductProof<T extends GroupElement<T>> implements Proof, Externalizable {
    private List<T> L;
    private List<T> R;
    private BigInteger a;
    private BigInteger b;

    public InnerProductProof() {
    }

    public InnerProductProof(ObjectInput in) throws IOException, ClassNotFoundException {
        readExternal(in);
    }

    public InnerProductProof(List<T> l, List<T> r, BigInteger a, BigInteger b) {
        L = l;
        R = r;
        this.a = a;
        this.b = b;
    }

    public List<T> getL() {
        return L;
    }

    public List<T> getR() {
        return R;
    }

    public BigInteger getA() {
        return a;
    }

    public BigInteger getB() {
        return b;
    }


    @Override
    public byte[] serialize() {
        List<byte[]> byteArrs = Stream.concat(L.stream(), R.stream()).map(GroupElement::canonicalRepresentation).collect(Collectors.toList());
        byteArrs.add(a.toByteArray());
        byteArrs.add(b.toByteArray());
        int totalBytes = byteArrs.stream().mapToInt(arr -> arr.length).sum();
        byte[] fullArray = new byte[totalBytes];
        int currIndex = 0;
        for (byte[] arr2 : byteArrs) {
            System.arraycopy(arr2, 0, fullArray, currIndex, arr2.length);
            currIndex += arr2.length;
        }
        return fullArray;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(L.size());
        for (T t : L) {
            byte[] x = t.canonicalRepresentation();
            out.write(x);
        }
        out.writeInt(R.size());
        for (T t : R) {
            byte[] x = t.canonicalRepresentation();
            out.write(x);
        }

        byte[] aBytes = a.toByteArray();
        out.writeInt(aBytes.length);
        out.write(aBytes);

        byte[] bBytes = b.toByteArray();
        out.writeInt(bBytes.length);
        out.write(bBytes);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void readExternal(ObjectInput in) throws IOException {
        int l = in.readInt();
        L = new ArrayList<>(l);
        for (int i = 0; i < l; i++) {
            BouncyCastleECPoint p = new BouncyCastleECPoint();
            p.readExternal(in);
            L.add((T) p);
        }

        int r = in.readInt();
        R = new ArrayList<>(r);
        for (int i = 0; i < r; i++) {
            BouncyCastleECPoint p = new BouncyCastleECPoint();
            p.readExternal(in);
            R.add((T) p);
        }

        int t1Len = in.readInt();
        byte[] t1 = new byte[t1Len];
        in.read(t1);
        a = new BigInteger(t1);

        int t2Len = in.readInt();
        byte[] t2 = new byte[t2Len];
        in.read(t2);
        b = new BigInteger(t2);
    }
}
