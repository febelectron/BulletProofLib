package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.*;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.junit.Test;

import java.math.BigDecimal;
import java.math.BigInteger;

/**
 * Created by electron on 01.05.18.
 */
public class RangeProofSerializationTest {

    @Test
    public void shouldDeserializedProofCorrect() throws VerificationFailedException {
        //this is a value to hide in Pedersen commitment (our balance).
        BigInteger balance = BigInteger.valueOf(13 * 100_000_000); // 13 coins.

        //this is a blinding factor (r).
        BigInteger randomness = ProofUtils.randomNumber();

        //we are using points on elliptic curve Secp256k1 here in Pedersen commitment. Can use any.
        //see below method GeneratorParams.generateParams() - we can use different curves for G and H.
        Group<BouncyCastleECPoint> curve = Secp256k1.INSTANCE;

        // bulletproof to be generated for value in [0 .. 2^N-1] range, N = 64 as below (should be power of 2).
        // 64 is the closest power of 2 to be more than 200 000 000 coins x 10^8 - our integer representation of the maximum balance.
        final int N = 64;
        GeneratorParams parameters = GeneratorParams.generateParams(N, curve);

        // get Pedersen commitment representation of our blinding factor and the value.
        PeddersenCommitment<BouncyCastleECPoint> witness = new PeddersenCommitment<>(parameters.getBase(), balance, randomness);

        // reset operations to 0 (just a performance test).
        BouncyCastleECPoint.addCount=0;
        BouncyCastleECPoint.expCount=0;

        // calculate actual Pedersen commitment value.
        GroupElement v = parameters.getBase().commit(balance, randomness);

        // calculate the proof.
        // todo: RangeProofProver can be a singleton service.
        RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);

        byte[] proofSer = RangeProof.serialize(proof);
        System.out.println("Proof size in bytes: " + proofSer.length);

        // output how many additions and multiplications we did (around ~ 1000 each, quite a lot).
        System.out.println(BouncyCastleECPoint.expCount);
        System.out.println(BouncyCastleECPoint.addCount);

        // todo: can be a singleton service.
        RangeProofVerifier verifier = new RangeProofVerifier();

        long t0 = System.currentTimeMillis();

        RangeProof proofDeserialized = RangeProof.deserialize(proofSer);

        // verify a bulletproof against a committed value using completely new objects (deserialized).
        // Throws an exception in case of various errors (I've checked).
        GeneratorParams parameters2 = GeneratorParams.generateParams(N, curve);
        GroupElement v2 = new BouncyCastleECPoint( ((BouncyCastleCurve)curve).getCurve().decodePoint(v.canonicalRepresentation())); //copy

        verifier.verify(parameters2, v2, proofDeserialized);
        System.out.println("Verify ended in " + (System.currentTimeMillis()-t0));
    }

}
