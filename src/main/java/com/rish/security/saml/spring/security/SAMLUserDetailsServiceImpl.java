package com.rish.security.saml.spring.security;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

//	private static final Logger log = Logger.getLogger(SAMLUserDetailsServiceImpl.class);

  public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
//    log.info("Login received for user {}", credential.getNameID().getValue());
    return new SAMLUserDetails(credential);
  }
}
