package services;


import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Properties;



public class Keys {
	
	public PublicKey publicKey;
	public PrivateKey privateKey; 
	public PublicKey publicKey2;
	public PrivateKey privateKey2;

	
    public static Properties getProp() throws IOException {
		Properties props = new Properties(); // Instancia a classes properties na variavel props
		InputStream file = Main.class.getResourceAsStream("/dados.properties"); // adiciona o arquivo a variavel
		props.load(file); //carrega o arquivo de propriedades na variavel
		return props;

	}

	    public Keys() throws NoSuchAlgorithmException, IOException {
	    	String bits;
	    	
	    	Properties prop = getProp(); //instanciando o props
	    	bits = prop.getProperty("prop.choice"); // cria a variavel e chama a propriedade do arquivo
	    	
	    	
	    	KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");//gera as chaves em RSA
	        generator.initialize(Integer.parseInt(bits, 10));// inicializa em 1024bits e converse a string em int
	        KeyPair keyPair = generator.generateKeyPair();//gera o par de chaves e coloca no keypair
	        
	        this.publicKey = keyPair.getPublic();//extraio 
	        this.privateKey = keyPair.getPrivate();//extraio
	        KeyPair keyPair2= generator.generateKeyPair();
	        this.publicKey2 = keyPair2.getPublic();
	        this.privateKey2 = keyPair2.getPrivate();
	    }


}


