package hyunul.boilerplate.member.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import hyunul.boilerplate.member.entity.Member;
import hyunul.boilerplate.member.repository.MemberRepository;

import java.time.LocalDateTime;

@Service
public class MemberService {
    @Autowired
    MemberRepository memberRepository;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    public void signup(Member member) {
        if (memberRepository.findByLoginId(member.getLoginId()) != null) {
            return;
        }
        Member signup = new Member();
        signup.setLoginId(member.getLoginId());
        signup.setRole("ROLE_USER");
        signup.setUserName(member.getUserName());
        signup.setPassword(bCryptPasswordEncoder.encode(member.getPassword()));
        signup.setEmail(member.getEmail());
        signup.setIsUsed("Y");
        signup.setIsDel("N");
        signup.setIsrtDate(LocalDateTime.now());

        memberRepository.save(signup);
    }
}
