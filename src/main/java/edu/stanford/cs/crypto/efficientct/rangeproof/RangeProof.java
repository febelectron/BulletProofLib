package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.innerproduct.InnerProductProof;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by buenz on 7/1/17.
 */
public class RangeProof<T extends GroupElement<T>> implements Proof, Externalizable {

    private T aI;
    private T s;
    private GeneratorVector<T> tCommits;
    private BigInteger tauX;
    private BigInteger mu;
    private BigInteger t;
    private InnerProductProof<T> productProof;

    public RangeProof() {
    }

    public RangeProof(ObjectInput in) throws IOException, ClassNotFoundException {
        readExternal(in);
    }

    public RangeProof(T aI, T s, GeneratorVector<T> tCommits, BigInteger tauX, BigInteger mu, BigInteger t, InnerProductProof<T> productProof) {
        this.aI = aI;
        this.s = s;
        this.tCommits = tCommits;
        this.tauX = tauX;
        this.mu = mu;
        this.t = t;
        this.productProof = productProof;
    }

    public T getaI() {
        return aI;
    }

    public T getS() {
        return s;
    }


    public BigInteger getTauX() {
        return tauX;
    }

    public BigInteger getMu() {
        return mu;
    }

    public BigInteger getT() {
        return t;
    }

    public InnerProductProof<T> getProductProof() {
        return productProof;
    }

    public GeneratorVector<T> gettCommits() {
        return tCommits;
    }

    @Override
    public byte[] serialize() {
        List<byte[]> byteArrs = new ArrayList<>();
        byteArrs.add(productProof.serialize());
        byteArrs.add(aI.canonicalRepresentation());
        byteArrs.add(s.canonicalRepresentation());
        tCommits.stream().map(GroupElement::canonicalRepresentation).forEach(byteArrs::add);
        BigInteger q = tCommits.getGroup().groupOrder();
        byteArrs.add(tauX.mod(q).toByteArray());
        byteArrs.add(mu.mod(q).toByteArray());
        byteArrs.add(t.mod(q).toByteArray());

        int totalBytes = byteArrs.stream().mapToInt(arr -> arr.length).sum();
        byte[] fullArray = new byte[totalBytes];
        int currIndex = 0;
        for (byte[] arr2 : byteArrs) {
            System.arraycopy(arr2, 0, fullArray, currIndex, arr2.length);
            currIndex += arr2.length;
        }
        return fullArray;
    }

    public static byte[] serialize(RangeProof proof) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            ObjectOutput out = new ObjectOutputStream(bos);
            proof.writeExternal(out);
            out.flush();
            return bos.toByteArray();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        finally {
            try {
                bos.close();
            } catch (IOException ex) {
                // ignore close exception
            }
        }
    }

    public static RangeProof deserialize(byte[] b) {
        ByteArrayInputStream bos = new ByteArrayInputStream(b);
        try {
            ObjectInput out = new ObjectInputStream(bos);
            return new RangeProof(out);
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        finally {
            try {
                bos.close();
            } catch (IOException ex) {
                // ignore close exception
            }
        }
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        productProof.writeExternal(out);
        ((BouncyCastleECPoint)aI).writeExternal(out);
        ((BouncyCastleECPoint)s).writeExternal(out);
        tCommits.writeExternal(out);

        byte[] t1 = tauX.toByteArray();
        out.writeInt(t1.length);
        out.write(t1);

        byte[] t2 = mu.toByteArray();
        out.writeInt(t2.length);
        out.write(t2);

        byte[] t3 = t.toByteArray();
        out.writeInt(t3.length);
        out.write(t3);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        productProof = new InnerProductProof<>(in);
        aI = (T) new BouncyCastleECPoint(in);
        s = (T) new BouncyCastleECPoint(in);
        tCommits = new GeneratorVector<>(in);

        int t1Len = in.readInt();
        byte[] t1 = new byte[t1Len];
        in.read(t1);
        tauX = new BigInteger(t1);

        int t2Len = in.readInt();
        byte[] t2 = new byte[t2Len];
        in.read(t2);
        mu = new BigInteger(t2);

        int t3Len = in.readInt();
        byte[] t3 = new byte[t3Len];
        in.read(t3);
        t = new BigInteger(t3);
    }

    public int numInts(){
        return 5;
    }
    public int numElements(){
        return 2+ tCommits.size()+productProof.getL().size()+productProof.getR().size();
    }
}
