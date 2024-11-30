local reconf = config['regexp']

reconf['CGP_RPOLL'] = {
    description = 'CommuniGate Pro RPOLL Received header',
    re = 'Received=/with RPOLL /{raw_header}'
}
