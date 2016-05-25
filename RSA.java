import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;


public class RSA {
	
	private BigInteger p;
	private BigInteger q;
	private BigInteger n;
	private BigInteger d;
	private BigInteger e;
	private BigInteger phiN;
	private int bitlength = 1024;
	private SecureRandom r;
	
	//Generate the keys
	public RSA() {
		r = new SecureRandom();
		p = BigInteger.probablePrime(bitlength, r);
		q = BigInteger.probablePrime(bitlength, r);
		n = p.multiply(p);
		phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e = BigInteger.probablePrime(bitlength/2, r);
		while (phiN.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phiN) < 0) {
			e.add(BigInteger.ONE);
		}
		d = e.modInverse(phiN);
	}
	
	public RSA(BigInteger e, BigInteger d, BigInteger n) {
		this.e = e;
		this.d = d;
		this.n = n;
	}
	
	@SuppressWarnings("deprecation")
	public static void main(String[] args) throws IOException{
		RSA rsa = new RSA();
		
		DataInputStream in=new DataInputStream(System.in);
		String data;
		System.out.println("What message would you like encrypted?");
		data = in.readLine();
		
		System.out.println("Message to encrypt: " + data);
		System.out.println("Message in bytes: " + bytesToString(data.getBytes()));
		
		//take those numbers and encrypt them
		byte[] cipher = rsa.encrypt(data.getBytes());
		System.out.println("Encrypted message in Bytes: " + bytesToString(cipher));
		
		//decrypt the numbers
		byte[] decipher = rsa.decrypt(cipher);
		System.out.println("Decrpyted message in Bytes: " + bytesToString(decipher));
		System.out.println("Decrypted message " + new String(decipher));
		
	}

	//convert the bytes into a string
	private static String bytesToString(byte[] ciphertext) {
		String test = "";
			for (byte b : ciphertext) {
				test += Byte.toString(b);
			}
		return test;
	}
	
	//encrypt message
	public byte[] encrypt(byte[] message) {
		return (new BigInteger(message)).modPow(e, n).toByteArray();
	}
	
	//decrypt message
	public byte[] decrypt(byte[] message) {
		return (new BigInteger(message)).modPow(d, n).toByteArray();
	}
}