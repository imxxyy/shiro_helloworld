package com.atguigu.shiro.hello;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ShiroHandler {

	@RequestMapping("/shiro-test")
	@RequiresRoles("admin")
	public String test(){
		
		System.out.println("test method");
		return "redirect:/list.jsp";
	}
	
	@RequestMapping("/shiro-login")
	public String doLogin(@RequestParam("username") String username,
			@RequestParam("password") String password) {

		// 获取当前用户
		Subject currentUser = SecurityUtils.getSubject();

		// 检验用户是否已经登陆
		if (!currentUser.isAuthenticated()) {
			// 若没有登录, 则把 用户名 和 密码 封装为一个 UsernamePasswordToken 对象.
			UsernamePasswordToken token = new UsernamePasswordToken(username,
					password);
			token.setRememberMe(true);
			try {
				// 执行登陆操作. 调用 Subject#login(UsernamePasswordToken) 方法.
				currentUser.login(token);
			} catch (AuthenticationException ae) {
				System.out.println("登陆失败: " + ae.getMessage());
				return "redirect:/login.jsp";
			}
		}

		return "list";
	}

}
