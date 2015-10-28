package com.atguigu.shiro.hello;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthorizingRealm{

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		//利用 token 传入的信息查询数据库. 得到其对应的记录
		UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;
		String username = usernamePasswordToken.getUsername();
		System.out.println("利用用户名: " + username + "查询数据库!");
		
		if (username==null) {
			throw new UnknownAccountException("用户名:" + username + "不存在!");
		}

		//若查询的有结果, 则返回 AuthenticationInfo 接口的 SimpleAuthenticationInfo 实现类对象
		//返回的认证信息
		String principal = username;
		//从数据表中查询得到的密码
//		Object hashedCredentials = "123";
		Object hashedCredentials = "3e866c3cbd704d109c3c27edc99b889b";
		//加密的盐值
		ByteSource credentialsSalt = ByteSource.Util.bytes("hahaha".getBytes());
		//当前 Realm 的 name, 通常通过调用 getName() 方法得到
		String realmName = getName();
		
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, hashedCredentials, credentialsSalt, realmName);
		
		
		return info;
	}
	
	public static void main(String[] args) {
		
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		
		
		Object principal = principals.getPrimaryPrincipal();
		
		Set<String> roles = new HashSet<>();
		roles.add("user");
		
		if ("admin".equals(principal)) {
			roles.add("admin");
		}
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRoles(roles);
		
		
		return info;
	}

}
