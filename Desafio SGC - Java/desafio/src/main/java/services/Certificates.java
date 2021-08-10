package services;


import java.math.BigInteger;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "certificates")

public class Certificates {
	  
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private BigInteger serialNumber;
	private String emissor;
	private String receptor;
	
	public BigInteger getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(BigInteger rootSerialNum) {
		this.serialNumber = rootSerialNum;
	}

	public String getEmissor() {
		return emissor;
	}

	public void setEmissor(String emissor) {
		this.emissor = emissor;
	}

	public String getReceptor() {
		return receptor;
	}

	public void setReceptor(String receptor) {
		this.receptor = receptor;
	}


}
