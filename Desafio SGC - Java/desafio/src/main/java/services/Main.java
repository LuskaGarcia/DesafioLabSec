package services;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;


public class Main {

	public static void main(String[] args) throws Exception{
		MessageDigest algorithm = MessageDigest.getInstance("SHA-256");//declara que o resumo sera em sha256
		//String senha = "admin"; 	
		InputStream is = Main.class.getResourceAsStream("/docdecod.txt"); //inicia o inputstream que armazena o arquivo
		byte[] buffer = new byte[8192]; // armazena o tamanho limite do arquivo
		int read = 0; 
		try {
			while( (read = is.read(buffer)) > 0) { //lendo o arquivo com o tamanho do buffer
				algorithm.update(buffer, 0, read);//vai fazendo a atualização do algorithm
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}	
		byte[] sha = algorithm.digest(); //resumo de algorithm
		BigInteger bigInt = new BigInteger(1, sha);
		String output = bigInt.toString(16);
		System.out.println("SHA-256: " + output);

		//byte messageDigest[] = algorithm.digest(doc.getBytes("UTF-8"));

	
		Keys chaves = new Keys();//instanciando a classe
		
		System.out.println(chaves.privateKey.toString());
		System.out.println(" \n");
		System.out.println(chaves.publicKey.toString());		

		
	}
	
	
	
	
}

	
	  
