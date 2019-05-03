package com.javaminiature.samldemo.configuration;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;


@ConfigurationProperties(prefix = "idp")
public class IDPConfiguration {
	
	private Metadata metadata=new Metadata();
	private String entityid;
	
	
	public String getEntityid() {
		return entityid;
	}

	public void setEntityid(String entityid) {
		this.entityid = entityid;
	}

	public Metadata getMetadata() {
		return metadata;
	}

	public void setMetadata(Metadata metadata) {
		this.metadata = metadata;
	}

	public static class Metadata {
		private List<String> url=new ArrayList<String>();

		public List<String> getUrl() {
			return url;
		}

		public void setUrl(List<String> url) {
			this.url = url;
		}
		
	}
}

