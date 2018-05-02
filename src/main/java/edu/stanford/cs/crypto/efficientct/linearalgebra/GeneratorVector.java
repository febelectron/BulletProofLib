package edu.stanford.cs.crypto.efficientct.linearalgebra;

import cyclops.collections.immutable.VectorX;
import cyclops.function.Monoid;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.circuit.groups.Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.circuit.groups.Secp256k1;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Created by buenz on 7/2/17.
 */
public class GeneratorVector<T extends GroupElement<T>> implements Iterable<T>, Externalizable {
    private VectorX<T> gs;
    private Group<T> group;
    private Monoid<T> ECPOINT_SUM ;

    public GeneratorVector() {
    }

    public GeneratorVector(ObjectInput in) throws IOException {
        readExternal(in);
    }

    public GeneratorVector(VectorX<T> gs, Group<T> group) {
        this.gs = gs;
        this.group=group;
        ECPOINT_SUM=Monoid.of(group.zero(), T::add);
    }

    private GeneratorVector<T> from(VectorX<T> gs) {
        return new GeneratorVector<>(gs, group);
    }

    public GeneratorVector<T> subVector(int start, int end) {
        return from(gs.subList(start, end));
    }

    public T commit(Iterable<BigInteger> exponents) {

        return gs.zip(exponents, T::multiply).reduce(ECPOINT_SUM);
    }


    public T sum() {
        return gs.reduce(ECPOINT_SUM);
    }

    public GeneratorVector<T> haddamard(Iterable<BigInteger> exponents) {
        return from(gs.zip(exponents, T::multiply));

    }

    public GeneratorVector<T> add(Iterable<T> b) {
        return from(gs.zip(b, T::add));
    }

    public T get(int i) {
        return gs.get(i);
    }

    public int size() {
        return gs.size();
    }

    public Stream<T> stream() {
        return gs.stream();
    }

    public VectorX<T> getVector() {
        return gs;
    }

    @Override
    public String toString() {
        return gs.map(T::stringRepresentation).toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof GeneratorVector)) {
            return false;
        }
        GeneratorVector vector = (GeneratorVector) obj;
        return gs.equals(vector.gs);
    }

    @Override
    public Iterator<T> iterator() {
        return gs.iterator();
    }

    public GeneratorVector<T> plus(T other) {
        return from(gs.plus(other));
    }

    public Group<T> getGroup() {
        return group;
    }
    public static <T extends GroupElement<T>> GeneratorVector<T> from(VectorX<T> gs,Group<T> group) {
        return new GeneratorVector<>(gs, group);
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(gs.size());
        for (T g : gs) {
            ((BouncyCastleECPoint)g).writeExternal(out);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public void readExternal(ObjectInput in) throws IOException {
        int len = in.readInt();
        List<T> ts = new ArrayList<>();
        for (int i = 0; i < len; i++) {
            ts.add((T) new BouncyCastleECPoint(in));
        }

        this.gs = VectorX.fromIterable(ts);
        this.group = (Group<T>) Secp256k1.INSTANCE;
        this.ECPOINT_SUM=Monoid.of(group.zero(), T::add);
    }
}
