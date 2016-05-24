import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;


public class RSA {
	
	private BigInteger n, d, e, phiN;
	
	private int bitlength = 1024;

	
	//Generate the keys
	public RSA(int bits) {
		bitlength = bits;
		SecureRandom r = new SecureRandom();
		BigInteger p = BigInteger.probablePrime(bitlength, r);
		BigInteger q = BigInteger.probablePrime(bitlength, r);
		BigInteger n = p.multiply(p);
		BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		BigInteger e = BigInteger.probablePrime(bitlength/2, r);
		while (phiN.gcd(e).intValue() > 1) {
			e = e.add(new BigInteger("1"));
		}
		d = e.modInverse(phiN);
	}
	
	//encrypt message
	public synchronized String encrypt(String message) {
		return (new BigInteger(message.getBytes())).modPow(e, n).toString();
	}
	
	//also encrypt message
	public synchronized BigInteger encrypt(BigInteger message) {
		return message.modPow(e, n);
	}
	
	public static void main(String[] args){
		RSA rsa = new RSA(1024);
		
		System.out.println("What message would you like encrypted?");
		String message = new Scanner(System.in).next();
		
		//convert message into numbers
		BigInteger cipher = new BigInteger(message.getBytes());
		
		//take those numbers and encrypt them
		BigInteger ciphertext = rsa.encrypt(cipher);
		
		System.out.println("Ciphertext: " + ciphertext);
		
	}
}