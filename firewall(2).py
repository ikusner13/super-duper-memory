from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
import csv
''' Add your imports here ... '''



log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  

Policies = namedtuple('Policy', ['id','src','dst'])

class Firewall (EventMixin):
    def make_policy_list(self,file):
        policies = []
        with open(policyFile, mode='r') as file:
            csvFile = csv.reader(file)
            for lines in csvFile:
                list = Policies(lines['id'], lines['mac_0'], lines['mac_1'])
                policies.append(list)
        return policies

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):    
        policies = self.make_policy_list(policyFile)

        for policy in policies:
            block = of.ofp_match()

            #policy id is 0
            block.dl_src = EthAddr(policy[1])
            block.dl_dst = EthAddr(policy[2])

            flow_mod = of.ofp_flow_mod()

            flow_mod.match = block

            actions = of.ofp_action_output(port=of.OFPP_NONE)
            flow_mod.actions.append(actions)

            flow_mod.priority = 15
            log.info("id=%s, src=%s, dst=%s" % (policy[0],policy[1], policy[2]))
            event.connection.send(flow_mod)
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
