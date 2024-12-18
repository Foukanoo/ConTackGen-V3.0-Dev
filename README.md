# ConTackGen-Plugin 2.0
ConTackGen is a contextual cyber-attack data generator for Weka.

## Installation

### Windows users
- You can watch the [video tutorial](https://youtu.be/nEsO7w1M3VI) to install the plugin.
- You can watch the [video tutorial](https://www.youtube.com/watch?v=bdFugbQBLxA&ab_channel=AdanRaynaud) for compiling the Contackgen plugin on Weka.

1. **Install [Weka](https://waikato.github.io/weka-wiki/downloading_weka/)**

2. **Install [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)**, then **open it** and:
   - Go to **`Settings`** : 
   - *General* -> Enable ``Expose daemon on tcp://localhost:2375 without TLS``
   - *Docker Engine:* -> Replace the existing JSON configuration with:
     ```json
     {
       "builder": {
         "gc": {
           "defaultKeepStorage": "20GB",
           "enabled": true
         }
       },
       "experimental": false,
       "hosts": [
         "tcp://0.0.0.0:2375"
       ]
     }
     ```
    Apply and Restart

3. **Install [JDK for Windows](https://www.oracle.com/java/technologies/downloads/#jdk22-windows)**

4. *(Optional) if you want to modify and recompile the plugin*, Install [Apache Ant](https://ant.apache.org/manual/install.html)

5. **Go to** [Usage](#usage) section to use the plugin

### Linux users

1. **Install [Weka](https://waikato.github.io/weka-wiki/downloading_weka/)**

2. **Install JDK:**
   ```
     sudo apt install default-jdk
   ```
3. **Install Docker:**
   - [Docker for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
   - [Post-installation steps for Linux](https://docs.docker.com/engine/install/linux-postinstall/)

4. *(Optional) if you want to modify and recompile the plugin*, Install **Ant**:
   ```
   sudo apt install ant
   ```

5. Go to [Usage](#usage) section to use the plugin

## Compatibility

ConTackGen 2.0 has been tested and is compatible with the following software versions:
- **Operating Systems**:
  - Ubuntu 18.04, 20.04, 22.04
  - Windows 10, Windows 11
  - Kali Linux 2022.4 
  - Linux Mint 21.3
- **Weka**: Version 3.9.6 and above
- **JDK**: Version 11 and above
- **Docker Desktop**: Version 4.29.0 and above for Windows
- **Apache Ant**: Version 1.10.2 and above

Please ensure that your system meets these requirements to avoid any issues during installation and operation of the plugin.

## Usage
**Download ConTackGen plugin**
- Download [latest release](https://github.com/HyperLan-git/ConTackGen-Plugin/releases) of ConTackGen plugin: `ConTackGen.zip`


**Install Plugin in Weka:**

   - Start Weka, go to `Tools` > `Package Manager`, select `Unofficial`, then `file/url` and choose `ConTackGen.zip`. Finally, click on `install` and restart Weka.

On the Weka main page, select `Workbench`, then `Generate`. Choose to select `ConTackGen` under the classification directory, then click `Generate` to start the data generator.
> **The first use will take more time**, depending on your internet connection as you need to pull the docker image (only for the first use)

![image](https://github.com/HyperLan-git/ConTackGen-Plugin/assets/60754866/0872381e-9ca9-4ccd-839f-06ae546c2bde)
> Select "Edit..." to view data details.

**Build the plugin**

If you want to modify the plugin you can modify the files then recompile the plugin:

In a terminal/command prompt at the root of the ConTackGen directory, execute :
```
ant make_package -Dpackage=ConTackGen
```
Plugin will be located inside `/ConTackGen/dist/ConTackGen.zip`

## Future Enhancements and Limitations

### Future Enhancements
1. **Simplify Windows Installation**:
   - In future releases, we plan to streamline the installation process for Windows users. Our goal is to eliminate the need for setting up Docker manually. This will make the initial setup quicker and more user-friendly.

2. **General Installation Improvements**:
   - We aim to simplify the installation process across all platforms. Enhancements will include automated scripts that reduce the number of steps required to get ConTackGen up and running, potentially integrating more elements into a single installation package.

3. **Expansion of Attack Types**:
   - Currently, ConTackGen supports one fully operational type of cyber-attack simulation, with another in development. Future versions will include multiple attack types, increasing the versatility and utility of the plugin for diverse cybersecurity training and research applications.

4. **SSH Implementation/Fix**:
   - Currently, the SSH attack does not match the project's standard for implementing a network attack. A future fix would be to use part of the MITM attack code to extract the SSH key and then decrypt it

5. **Improve differentiation between the 2 attacks**:
   - Currently, DDoS and MITM attacks give us the same data when we compile them. Future versions will include multiple data types to differentiate between the two attacks


### Limitations
- The current version requires manual installation steps that may be challenging for users unfamiliar with Docker or development environments.
- Limited to a small number of cyber-attack simulations, which may not cover all the potential scenarios users might need to simulate for comprehensive training or testing.

By addressing these limitations in the upcoming ConTackGen 3.0, we hope to enhance user experience and broaden the applicability of the tool in educational and professional settings.

## Authors
> Version 1.0:
- Mathieu SALLIOT (mathieu.salliot@epita.fr)
- Pierre BLAIS (pierre.blais@epita.fr)
- Luis RIBEIRO (luis.rebeiro@epita.fr)
- Benjamin ALONZEAU (benjamin.alonzo@epita.fr)

> Version 2.0(19/04/2024):
- Aboubekre Sayoud (aboubekre.sayoud@epita.fr)
- Simon Defoort (simon.defoort@epita.fr)
- Natale Mamberti (natale.mamberti@epita.fr)
- Youness Rekik (youness.rekik@epita.fr)

> Version 3.0:
- William BENEDICO (william.benedico@epita.fr)
- Adan RAYNAUD (adan.raynaud@epita.fr)
- Frederic DINAHET (frederic.dinahet@epita.fr)
- Rayan ROCHDI (rayan.rochdi@epita.fr)

Supervised by **Nidà MEDDOURI** (nida.meddouri@epita.fr)
