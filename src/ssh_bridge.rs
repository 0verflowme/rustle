use russh::Channel;

pub type DirectTcpipChannel = Channel<russh::client::Msg>;
