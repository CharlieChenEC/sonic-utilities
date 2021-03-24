import click
from clear.main import AliasedGroup,cli
from clear.main import run_command

#
# This group houses Spanning_tree commands and subgroups
#
@cli.group(cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def spanning_tree(ctx):
    '''Clear Spanning-tree counters'''
    pass

@spanning_tree.group('statistics', cls=AliasedGroup, invoke_without_command=True)
@click.pass_context
def stp_clr_stats(ctx):
    if ctx.invoked_subcommand is None:
        command = 'sudo stpctl clrstsall'
        run_command(command)
    pass

@stp_clr_stats.command('interface')
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.pass_context
def stp_clr_stats_intf(ctx, interface_name):
    command = 'sudo stpctl clrstsintf ' + interface_name
    run_command(command)
    pass

@stp_clr_stats.command('vlan')
@click.argument('vlan_id', metavar='<vlan_id>', required=True)
@click.pass_context
def stp_clr_stats_vlan(ctx, vlan_id):
    command = 'sudo stpctl clrstsvlan ' + vlan_id
    run_command(command)
    pass

@stp_clr_stats.command('vlan-interface')
@click.argument('vlan_id', metavar='<vlan_id>', required=True)
@click.argument('interface_name', metavar='<interface_name>', required=True)
@click.pass_context
def stp_clr_stats_vlan_intf(ctx, vlan_id, interface_name):
    command = 'sudo stpctl clrstsvlanintf ' + vlan_id + ' ' + interface_name
    run_command(command)
    pass
