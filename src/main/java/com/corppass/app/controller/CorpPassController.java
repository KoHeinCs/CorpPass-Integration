package com.corppass.app.controller;

import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.corppass.app.service.CorpPassService;

@Controller
public class CorpPassController {
	
	@Autowired
	public CorpPassService corpPassService;
	
	@GetMapping({"/","","/login"})
	public String login() {
		return "login";
	}
	
    @GetMapping("/myinfopage")
    @ResponseBody
    public String goSgMyInfoSite() {

    	
    	String url="https://test.api.myinfo.gov.sg/serviceauth/myinfo-biz/v1/authorise?";
    	String client_id = "client_id=STG2-MYINFO-SELF-TEST&";
    	String purpose ="purpose=demonstrating%20MyInfo%20Business%20APIs&";
    	String redirect_uri = "redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcallback&";
    	String response_type ="response_type=code&";
    	String scope = "scope=name%20sex%20race%20nationality%20dob%20regadd%20housingtype%20email%20mobileno%20marital%20edulevel%20basic-profile%20addresses%20appointments&";
    	String state ="state=123";
    	
    	
    	
    	StringBuilder sb=new StringBuilder(url);
    	sb.append(client_id);
    	sb.append(purpose);
    	sb.append(redirect_uri);
    	sb.append(response_type);
    	sb.append(scope);
    	sb.append(state);
    	
    	return sb.toString();
    }
    
    
    
    @GetMapping("/callback")
    @ResponseBody
    public ModelAndView callMyInfoWithCode(@RequestParam(value= "code", required = false) String code,HttpServletResponse httpServletResp) {

    
    String result = null;
      
      if(code == null ) {
    	  result = "redirect:/login";
      }else { 
    	JSONObject  entyty_person = corpPassService.getMyInfodata(code);
    	System.out.println("************************* entity data from CorpPass ************************** ");
    	System.out.println(entyty_person.toString());
    	result = "success";
    	
      }
     
      
      return new ModelAndView(result == null? "redirect:/login" : result);
    	
    }

}
