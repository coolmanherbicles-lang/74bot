import React from 'react';
import { motion, useScroll, useTransform, Variants } from 'framer-motion';
import { Terminal, Shield, Fingerprint, Network, Search, Database, Lock, Globe, Server, Cpu, Wifi } from 'lucide-react';

const fadeIn: Variants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: "easeOut" } }
};

const staggerContainer: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1
    }
  }
};

const commands = [
  {
    cmd: '/email',
    desc: 'Deep email OSINT. Cross-references breaches, domain reputation, DNS records, and Gravatar.',
    icon: <Search className="w-4 h-4" />
  },
  {
    cmd: '/breach',
    desc: 'Full breach intel. Email or domain pivot across HIBP, COMB, and BreachDirectory.',
    icon: <Database className="w-4 h-4" />
  },
  {
    cmd: '/username',
    desc: 'Hunt a username across 70+ platforms combined with a comprehensive breach sweep.',
    icon: <Fingerprint className="w-4 h-4" />
  },
  {
    cmd: '/discordid',
    desc: 'Snowflake decode, Discord user lookup, and full breach chain (COMB, BD, HIBP).',
    icon: <Terminal className="w-4 h-4" />
  },
  {
    cmd: '/phone',
    desc: 'Phone OSINT: Carrier routing, regional validation, and breach sweep.',
    icon: <Network className="w-4 h-4" />
  },
  {
    cmd: '/ip',
    desc: 'Full IP intel: Geo, ASN, Shodan, AbuseIPDB, VirusTotal, Tor, and VPN detection.',
    icon: <Globe className="w-4 h-4" />
  },
  {
    cmd: '/wifi',
    desc: 'WiFi OSINT: Wigle SSID/BSSID lookups, MAC vendor resolution, and sweep.',
    icon: <Wifi className="w-4 h-4" />
  },
  {
    cmd: '/whitelist',
    desc: 'Owner-only access control mechanism. Revoke or grant access instantly.',
    icon: <Lock className="w-4 h-4" />
  }
];

const sources = ['COMB', 'BreachDirectory', 'HIBP', 'ProxyNova', 'AbuseIPDB', 'VirusTotal', 'Shodan', 'Wigle'];

export default function Home() {
  const { scrollYProgress } = useScroll();
  const yBg = useTransform(scrollYProgress, [0, 1], ['0%', '50%']);

  return (
    <div className="min-h-screen bg-background text-foreground overflow-x-hidden selection:bg-primary selection:text-primary-foreground font-sans relative">
      <div className="scanline"></div>
      
      {/* Background Grid Elements */}
      <div className="fixed inset-0 bg-grid opacity-30 z-0 pointer-events-none"></div>
      
      {/* Top Navbar */}
      <nav className="fixed top-0 left-0 right-0 z-50 glass-panel border-b-0 border-white/5 py-4 px-6 md:px-12 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" />
          <span className="font-mono text-sm tracking-wider font-bold">74BOT_OSINT</span>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono text-muted-foreground uppercase tracking-widest">
          <span className="hidden md:inline-flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse"></span>
            System Online
          </span>
          <span className="px-3 py-1 bg-white/5 border border-white/10 rounded-sm">INVITE ONLY</span>
        </div>
      </nav>

      <main className="relative z-10 pt-32 pb-24 px-6 md:px-12 max-w-7xl mx-auto flex flex-col gap-32">
        
        {/* Hero Section */}
        <section className="min-h-[70vh] flex flex-col justify-center">
          <motion.div 
            initial="hidden" 
            animate="visible" 
            variants={staggerContainer}
            className="max-w-3xl"
          >
            <motion.div variants={fadeIn} className="inline-block mb-6">
              <div className="font-mono text-primary text-sm tracking-widest uppercase border border-primary/20 bg-primary/5 px-3 py-1 flex items-center gap-2">
                <Cpu className="w-4 h-4" /> Classified Access
              </div>
            </motion.div>
            
            <motion.h1 variants={fadeIn} className="text-5xl md:text-7xl lg:text-8xl font-medium tracking-tight mb-6 leading-[1.1]">
              Deep Intel.<br />
              <span className="text-muted-foreground">Zero Friction.</span>
            </motion.h1>
            
            <motion.p variants={fadeIn} className="text-lg md:text-xl text-muted-foreground max-w-xl mb-10 leading-relaxed">
              74bot is a private Discord OSINT intelligence terminal. Access breach databases, leaked credentials, IP intel, and deep identity lookups directly from your client. 
            </motion.p>
            
            <motion.div variants={fadeIn} className="flex flex-col sm:flex-row gap-4">
              <button className="bg-foreground text-background font-mono text-sm uppercase tracking-wider font-bold px-8 py-4 hover:bg-primary hover:text-primary-foreground transition-all duration-300 flex items-center justify-center gap-2 group">
                <Lock className="w-4 h-4 group-hover:scale-110 transition-transform" />
                Request Whitelist
              </button>
              <button className="glass-panel text-foreground font-mono text-sm uppercase tracking-wider font-bold px-8 py-4 hover:bg-white/5 transition-all duration-300 border border-white/10 flex items-center justify-center gap-2">
                <Server className="w-4 h-4" />
                View Status
              </button>
            </motion.div>
          </motion.div>
        </section>

        {/* Console Demo / Vibe Section */}
        <motion.section 
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: "-100px" }}
          variants={fadeIn}
          className="relative"
        >
          <div className="glass-panel p-1 rounded-sm border border-white/10 overflow-hidden shadow-2xl shadow-primary/5">
            <div className="bg-[#0a0a0c] p-4 flex items-center gap-2 border-b border-white/5">
              <div className="w-3 h-3 rounded-full bg-white/20"></div>
              <div className="w-3 h-3 rounded-full bg-white/20"></div>
              <div className="w-3 h-3 rounded-full bg-white/20"></div>
              <div className="ml-4 font-mono text-xs text-muted-foreground">discord_terminal — 74bot — 80x24</div>
            </div>
            <div className="p-6 md:p-8 font-mono text-sm md:text-base leading-relaxed bg-[#0a0a0c] text-muted-foreground min-h-[300px]">
              <div className="flex flex-col gap-2">
                <p><span className="text-primary">root@74bot</span>:~$ /email target@example.com</p>
                <p className="text-white/40">[*] Initiating deep sweep across COMB, HIBP, BreachDirectory...</p>
                <p className="text-white/40">[*] Checking domain reputation...</p>
                <div className="mt-4 border-l-2 border-primary pl-4 text-white/80">
                  <p className="text-primary font-bold mb-2">TARGET ACQUIRED</p>
                  <p>Breaches found: 4</p>
                  <p>Domain rep: Clean</p>
                  <p>Associated aliases: 2</p>
                  <p className="text-xs text-white/40 mt-2">[ Data redacted for public view ]</p>
                </div>
                <p className="mt-4 animate-pulse">_</p>
              </div>
            </div>
          </div>
        </motion.section>

        {/* Capabilities Grid */}
        <section className="relative z-10">
          <motion.div 
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true, margin: "-100px" }}
            variants={staggerContainer}
          >
            <motion.h2 variants={fadeIn} className="text-3xl md:text-5xl font-medium tracking-tight mb-16 border-b border-white/10 pb-8 flex items-center gap-4">
              <Terminal className="text-primary" /> Command Core
            </motion.h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {commands.map((cmd, i) => (
                <motion.div 
                  key={cmd.cmd}
                  variants={fadeIn}
                  className="glass-panel p-6 border border-white/5 hover:border-primary/30 transition-colors duration-500 group flex flex-col"
                >
                  <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 bg-white/5 text-primary border border-white/5 rounded-sm group-hover:bg-primary/10 transition-colors">
                      {cmd.icon}
                    </div>
                    <h3 className="font-mono text-lg font-bold text-white group-hover:text-primary transition-colors">{cmd.cmd}</h3>
                  </div>
                  <p className="text-muted-foreground text-sm leading-relaxed flex-grow">
                    {cmd.desc}
                  </p>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </section>

        {/* Data Sources */}
        <section className="py-24 border-t border-white/5 relative overflow-hidden">
          <div className="absolute inset-0 bg-primary/5 blur-3xl opacity-20 pointer-events-none rounded-full transform scale-150 translate-y-1/2"></div>
          <motion.div 
            initial="hidden"
            whileInView="visible"
            viewport={{ once: true }}
            variants={staggerContainer}
            className="flex flex-col items-center text-center relative z-10"
          >
            <motion.h3 variants={fadeIn} className="font-mono text-sm text-primary uppercase tracking-widest mb-8">Intelligence Feeds</motion.h3>
            <motion.div variants={fadeIn} className="flex flex-wrap justify-center gap-4 md:gap-8 max-w-4xl">
              {sources.map((source) => (
                <div key={source} className="font-sans text-xl md:text-3xl font-bold text-white/20 hover:text-white transition-colors duration-300">
                  {source}
                </div>
              ))}
            </motion.div>
          </motion.div>
        </section>
        
      </main>

      {/* Footer */}
      <footer className="border-t border-white/5 py-8 text-center text-xs font-mono text-white/30 relative z-10 glass-panel">
        <p>74BOT CLASSIFIED INTEL TERMINAL // {new Date().getFullYear()} // UNAUTHORIZED ACCESS PROHIBITED</p>
      </footer>
    </div>
  );
}
