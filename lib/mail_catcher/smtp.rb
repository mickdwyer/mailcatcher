require 'eventmachine'

class MailCatcher::Smtp < EventMachine::Protocols::SmtpServer
  # override the provided implementation so we can load certs/keys & start tls.
  def process_starttls
    if @@parms[:starttls]
      if @state.include?(:starttls)
        send_data "503 TLS Already negotiated\r\n"
      elsif ! @state.include?(:ehlo)
        send_data "503 EHLO required before STARTTLS\r\n"
      else
        send_data "220 Start TLS negotiation\r\n"
        start_tls @@parms.select { |k,v| [:private_key_file, :cert_chain_file, :verify_peer].include?(k) }
        @state << :starttls
      end
    else
      process_unknown
    end
  end

  def current_message
    @current_message ||= {}
  end

  def receive_reset
    @current_message = nil
    true
  end

  def receive_sender(sender)
    current_message[:sender] = sender
    true
  end

  def receive_recipient(recipient)
    current_message[:recipients] ||= []
    current_message[:recipients] << recipient
    true
  end

  def receive_data_chunk(lines)
    current_message[:source] ||= ""
    current_message[:source] += lines.join("\n")
    true
  end

  def receive_message
    MailCatcher::Mail.add_message current_message
    puts "==> SMTP: Received message from '#{current_message[:sender]}' (#{current_message[:source].length} bytes)"
    true
  rescue
    puts "*** Error receiving message: #{current_message.inspect}"
    puts "    Exception: #{$!}"
    puts "    Backtrace:"
    $!.backtrace.each do |line|
      puts "       #{line}"
    end
    puts "    Please submit this as an issue at http://github.com/sj26/mailcatcher/issues"
    false
  ensure
    @current_message = nil
  end
end
