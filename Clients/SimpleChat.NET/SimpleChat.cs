/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 1997-2004 Apple Computer, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

    Change History (most recent first):
    
$Log: SimpleChat.cs,v $
Revision 1.6  2006/08/14 23:24:21  cheshire
Re-licensed mDNSResponder daemon source code under Apache License, Version 2.0

Revision 1.5  2004/09/13 19:37:42  shersche
Change code to reflect namespace and type changes to dnssd.NET library

Revision 1.4  2004/09/11 05:42:56  shersche
don't reset SelectedIndex in OnRemove

Revision 1.3  2004/09/11 00:38:58  shersche
DNSService APIs now expect port in host format

Revision 1.2  2004/07/19 22:08:53  shersche
Fixed rdata->int conversion problem in QueryRecordReply

Revision 1.1  2004/07/19 07:57:08  shersche
Initial revision



*/

using System;
using System.Drawing;
using System.Collections;
using System.ComponentModel;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Data;
using System.Text;
using Apple.DNSSD;

namespace SimpleChat.NET
{
	/// <summary>
	/// Summary description for Form1.
	/// </summary>
	/// 

	//
	// PeerData
	//
	// Holds onto the information associated with a peer on the network
	//
	public class PeerData
	{
		public int			InterfaceIndex;
		public String		Name;
		public String		Type;
		public String		Domain;
		public IPAddress	Address;
		public int			Port;

		public override String
		ToString()
		{
			return Name;
		}

		public override bool
		Equals(object other)
		{
			bool result = false;

			if (other != null)
			{
				if ((object) this == other)
				{
					result = true;
				}
				else if (other is PeerData)
				{
					PeerData otherPeerData = (PeerData) other;

					result = (this.Name == otherPeerData.Name);
				}
			}

			return result;
		}
	
		public override int
		GetHashCode()
		{
			return Name.GetHashCode();
		}
	};

	//
	// ResolveData
	//
	// Holds onto the information associated with the resolution
	// of a DNSService
	//
	public class ResolveData
	{
		public int		InterfaceIndex;
		public String	FullName;
		public String	HostName;
		public int		Port;
		public Byte[]	TxtRecord;

		public override String
		ToString()
		{
			return FullName;
		}
	};


	//
	// SocketStateObject
	//
	// Holds onto the data associated with an asynchronous
	// socket operation
	//
	class SocketStateObject
	{
		public const int		BUFFER_SIZE = 1024;
		private Socket			m_socket;
		public byte[]			m_buffer;
		public bool				m_complete;
		public StringBuilder	m_sb = new StringBuilder();

		public SocketStateObject(Socket socket)
		{
			m_buffer	= new byte[BUFFER_SIZE];
			m_complete	= false;
			m_socket	= socket;
		}

		public Socket
		WorkSocket
		{
			get
			{
				return m_socket;
			}
		}
	}
	public class Form1 : System.Windows.Forms.Form
	{
		private System.Windows.Forms.ComboBox comboBox1;
		private System.Windows.Forms.TextBox textBox2;
		private System.Windows.Forms.Button button1;
		private System.Windows.Forms.Label label1;
		private ServiceRef registrar = null;
		private ServiceRef browser = null;
		private ServiceRef resolver = null;
		private String					myName;
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.Container components = null;
		
		//
		// These all of our callbacks.  These are invoked in the context
		// of the main (GUI) thread.  The DNSService callbacks Invoke()
		// them
		delegate void RegisterServiceCallback(String name);
		delegate void AddPeerCallback(PeerData data);
		delegate void RemovePeerCallback(PeerData data);
		delegate void ResolveServiceCallback(ResolveData data);
		delegate void ResolveAddressCallback(System.Net.IPAddress address);
		delegate void ReadMessageCallback(String data);

		RegisterServiceCallback	registerServiceCallback;
		AddPeerCallback			addPeerCallback;
		RemovePeerCallback		removePeerCallback;
		ResolveServiceCallback  resolveServiceCallback;
		ResolveAddressCallback	resolveAddressCallback;
		ReadMessageCallback		readMessageCallback;
		private System.Windows.Forms.RichTextBox richTextBox1;

		//
		// The socket that we will be reading data from
		//
		Socket socket = null;

		//
		// OnRegisterService
		//
		// The name that we are passed might be different than the
		// name we called Register with.  So we hold onto this name
		// rather than the name we Register with.
		//
		// This is called (indirectly) from OnRegisterReply().
		//
		private void
		OnRegisterService
				(
				String name
				)
		{
			myName = name;
		}

		//
		// OnAddPeer
		//
		// Called when DNSServices detects a new P2P Chat peer has
		// joined.
		//
		// This is called (indirectly) from OnBrowseReply()
		//
		private void
		OnAddPeer
				(
				PeerData  peer
				)
		{
			comboBox1.Items.Add(peer);

			if (comboBox1.Items.Count == 1)
			{
				comboBox1.SelectedIndex = 0;
			}
		}

		//
		// OnRemovePeer
		//
		// Called when DNSServices detects a P2P peer has left
		// the network
		//
		// This is called (indirectly) from OnBrowseReply()
		//
		private void
		OnRemovePeer
				(
				PeerData  peer
				)
		{
			comboBox1.Items.Remove(peer);
		}

		//
		// OnResolveService
		//
		// Called when DNSServices has resolved a service.
		//
		// This is called (indirectly) from OnResolveService()
		//
		private void
		OnResolveService
				(
				ResolveData data
				)
		{
			resolver.Dispose();

			PeerData peer = (PeerData) comboBox1.SelectedItem;

			peer.Port = data.Port;

			try
			{
				resolver = DNSService.QueryRecord(0, 0, data.HostName, /* ns_t_a */ 1, /* ns_t_c */ 1, new DNSService.QueryRecordReply(OnQueryRecordReply));
			}
			catch
			{
				MessageBox.Show("QueryRecord Failed", "Error");
				Application.Exit();
			}
		}

		//
		// OnResolveAddress
		//
		// Called when DNSServices has finished a query operation
		//
		// This is called (indirectly) from OnQueryRecordReply()
		//
		private void
		OnResolveAddress
				(
				System.Net.IPAddress address
				)
		{
			resolver.Dispose();

			PeerData peer = (PeerData) comboBox1.SelectedItem;

			peer.Address = address;
		}

		//
		// OnReadMessage
		//
		// Called when there is data to be read on a socket
		//
		// This is called (indirectly) from OnReadSocket()
		//
		private void
		OnReadMessage
				(
				String msg
				)
		{
			int rgb = 0;

			for (int i = 0; i < msg.Length && msg[i] != ':'; i++)
			{
				rgb = rgb ^ ((int) msg[i] << (i % 3 + 2) * 8);
			}

			Color color = Color.FromArgb(rgb & 0x007F7FFF);

			richTextBox1.SelectionColor = color;
			
			richTextBox1.AppendText(msg + "\n");
		}

		//
		// OnRegisterReply
		//
		// Called by DNSServices core as a result of DNSService.Register()
		// call
		//
		// This is called from a worker thread by DNSService core.
		//
		private void
		OnRegisterReply
					(
					ServiceRef		sdRef,
					ServiceFlags	flags,
					ErrorCode		errorCode,
					String			name,
					String			regtype,
					String			domain)
		{
			if (errorCode == ErrorCode.NoError)
			{
				Invoke(registerServiceCallback, new Object[]{name});
			}
			else
			{
				MessageBox.Show("OnRegisterReply returned an error code " + errorCode, "Error");
			}
		}


		//
		// OnBrowseReply
		//
		// Called by DNSServices core as a result of DNSService.Browse()
		// call
		//
		// This is called from a worker thread by DNSService core.
		//
		private void
		OnBrowseReply
					(
					ServiceRef		sdRef,
					ServiceFlags	flags,
					int				interfaceIndex,
					ErrorCode		errorCode,
					String			name,
					String			type,
					String			domain)
		{
			if (errorCode == ErrorCode.NoError)
			{
				PeerData peer = new PeerData();

				peer.InterfaceIndex = interfaceIndex;
				peer.Name = name;
				peer.Type = type;
				peer.Domain = domain;
				peer.Address = null;

				if ((flags & ServiceFlags.Add) != 0)
				{
					Invoke(addPeerCallback, new Object[]{peer});
				}
				else if ((flags == 0) || ((flags & ServiceFlags.MoreComing) != 0))
				{
					Invoke(removePeerCallback, new Object[]{peer});
				}
			}
			else
			{
				MessageBox.Show("OnBrowseReply returned an error code " + errorCode, "Error");
			}
		}

		//
		// OnResolveReply
		//
		// Called by DNSServices core as a result of DNSService.Resolve()
		// call
		//
		// This is called from a worker thread by DNSService core.
		//
		private void
		OnResolveReply
			(
			ServiceRef		sdRef,
			ServiceFlags	flags,
			int				interfaceIndex,
			ErrorCode		errorCode,
			String			fullName,
			String			hostName,
			int				port,
			Byte[]			txtRecord
			)
		{
			if (errorCode == ErrorCode.NoError)
			{
				ResolveData data = new ResolveData();

				data.InterfaceIndex = interfaceIndex;
				data.FullName		= fullName;
				data.HostName		= hostName;
				data.Port			= port;
				data.TxtRecord		= txtRecord;

				Invoke(resolveServiceCallback, new Object[]{data});
			}
			else
			{
				MessageBox.Show("OnResolveReply returned an error code: " + errorCode, "Error");
			}
		}

		//
		// OnQueryRecordReply
		//
		// Called by DNSServices core as a result of DNSService.QueryRecord()
		// call
		//
		// This is called from a worker thread by DNSService core.
		//
		private void
		OnQueryRecordReply
			(
			ServiceRef		sdRef,
			ServiceFlags	flags,
			int				interfaceIndex,
			ErrorCode		errorCode,	
			String			fullName,
			int				rrtype,
			int				rrclass,
			Byte[]			rdata,
			int				ttl
			)
		{
			if (errorCode == ErrorCode.NoError)
			{
				uint bits					= BitConverter.ToUInt32(rdata, 0);
				System.Net.IPAddress data	= new System.Net.IPAddress(bits);
		
				Invoke(resolveAddressCallback, new Object[]{data});
			}
			else
			{
				MessageBox.Show("OnQueryRecordReply returned an error code: " + errorCode, "Error");
			}
		}

		//
		// OnReadSocket
		//
		// Called by the .NET core when there is data to be read on a socket
		//
		// This is called from a worker thread by the .NET core
		//
		private void
		OnReadSocket
				(
				IAsyncResult ar
				)
		{
			SocketStateObject so = (SocketStateObject) ar.AsyncState;
			Socket s = so.WorkSocket;

			try
			{
				if (s == null)
				{
					return;
				}

				int read = s.EndReceive(ar);

				if (read > 0)
				{
					String msg = Encoding.UTF8.GetString(so.m_buffer, 0, read);
					
					Invoke(readMessageCallback, new Object[]{msg});
				}

				s.BeginReceive(so.m_buffer, 0, SocketStateObject.BUFFER_SIZE, 0, new AsyncCallback(OnReadSocket), so);
			}
			catch
			{
			}
		}


		public Form1()
		{
			//
			// Required for Windows Form Designer support
			//
			InitializeComponent();

			registerServiceCallback	= new RegisterServiceCallback(OnRegisterService);
			addPeerCallback			= new AddPeerCallback(OnAddPeer);
			removePeerCallback		= new RemovePeerCallback(OnRemovePeer);
			resolveServiceCallback	= new ResolveServiceCallback(OnResolveService);
			resolveAddressCallback	= new ResolveAddressCallback(OnResolveAddress);
			readMessageCallback		= new ReadMessageCallback(OnReadMessage);

			this.Load += new System.EventHandler(this.Form1_Load);

			this.AcceptButton = button1;
		}

		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		protected override void
		Dispose( bool disposing )
		{
			if( disposing )
			{
				if (components != null) 
				{
					components.Dispose();
				}

				if (registrar != null)
				{
					registrar.Dispose();
				}

				if (browser != null)
				{
					browser.Dispose();
				}
			}
			base.Dispose( disposing );
		}

		#region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
			this.comboBox1 = new System.Windows.Forms.ComboBox();
			this.textBox2 = new System.Windows.Forms.TextBox();
			this.button1 = new System.Windows.Forms.Button();
			this.label1 = new System.Windows.Forms.Label();
			this.richTextBox1 = new System.Windows.Forms.RichTextBox();
			this.SuspendLayout();
			// 
			// comboBox1
			// 
			this.comboBox1.Anchor = ((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
				| System.Windows.Forms.AnchorStyles.Right);
			this.comboBox1.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
			this.comboBox1.Location = new System.Drawing.Point(59, 208);
			this.comboBox1.Name = "comboBox1";
			this.comboBox1.Size = new System.Drawing.Size(224, 21);
			this.comboBox1.Sorted = true;
			this.comboBox1.TabIndex = 5;
			this.comboBox1.SelectedIndexChanged += new System.EventHandler(this.comboBox1_SelectedIndexChanged);
			// 
			// textBox2
			// 
			this.textBox2.Anchor = ((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
				| System.Windows.Forms.AnchorStyles.Right);
			this.textBox2.Location = new System.Drawing.Point(8, 248);
			this.textBox2.Name = "textBox2";
			this.textBox2.ScrollBars = System.Windows.Forms.ScrollBars.Horizontal;
			this.textBox2.Size = new System.Drawing.Size(192, 20);
			this.textBox2.TabIndex = 2;
			this.textBox2.Text = "";
			this.textBox2.TextChanged += new System.EventHandler(this.textBox2_TextChanged);
			// 
			// button1
			// 
			this.button1.Anchor = (System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right);
			this.button1.Enabled = false;
			this.button1.Location = new System.Drawing.Point(208, 248);
			this.button1.Name = "button1";
			this.button1.TabIndex = 3;
			this.button1.Text = "Send";
			this.button1.Click += new System.EventHandler(this.button1_Click);
			// 
			// label1
			// 
			this.label1.Anchor = (System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left);
			this.label1.Location = new System.Drawing.Point(8, 210);
			this.label1.Name = "label1";
			this.label1.Size = new System.Drawing.Size(48, 16);
			this.label1.TabIndex = 4;
			this.label1.Text = "Talk To:";
			// 
			// richTextBox1
			// 
			this.richTextBox1.Anchor = (((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
				| System.Windows.Forms.AnchorStyles.Left) 
				| System.Windows.Forms.AnchorStyles.Right);
			this.richTextBox1.Location = new System.Drawing.Point(8, 8);
			this.richTextBox1.Name = "richTextBox1";
			this.richTextBox1.ReadOnly = true;
			this.richTextBox1.Size = new System.Drawing.Size(272, 184);
			this.richTextBox1.TabIndex = 1;
			this.richTextBox1.Text = "";
			// 
			// Form1
			// 
			this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
			this.ClientSize = new System.Drawing.Size(292, 273);
			this.Controls.AddRange(new System.Windows.Forms.Control[] {
																		  this.richTextBox1,
																		  this.label1,
																		  this.button1,
																		  this.textBox2,
																		  this.comboBox1});
			this.Name = "Form1";
			this.Text = "SimpleChat.NET";
			this.ResumeLayout(false);

		}
		#endregion

		private void Form1_Load(object sender, EventArgs e) 
		{
			IPEndPoint localEP = new IPEndPoint(System.Net.IPAddress.Any, 0);
			
			//
			// create the socket and bind to INADDR_ANY
			//
			socket	= new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
			socket.Bind(localEP);
			localEP = (IPEndPoint) socket.LocalEndPoint;

			//
			// start asynchronous read
			//
			SocketStateObject so = new SocketStateObject(socket);
			socket.BeginReceive(so.m_buffer, 0, SocketStateObject.BUFFER_SIZE, 0, new AsyncCallback(this.OnReadSocket), so);   

			try
			{
				//
				// start the register and browse operations
				//
				registrar	=	DNSService.Register(0, 0, System.Environment.UserName, "_p2pchat._udp", null, null, localEP.Port, null, new DNSService.RegisterReply(OnRegisterReply));
				browser		=	DNSService.Browse(0, 0, "_p2pchat._udp", null, new DNSService.BrowseReply(OnBrowseReply));			
			}
			catch
			{
				MessageBox.Show("DNSServices Not Available", "Error");
				Application.Exit();
			}
		}

		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		[STAThread]
		static void Main() 
		{
			Application.Run(new Form1());
		}

		//
		// send the message to a peer
		//
		private void button1_Click(object sender, System.EventArgs e)
		{
			PeerData peer = (PeerData) comboBox1.SelectedItem;

			String message = myName + ": " + textBox2.Text;

			Byte[] bytes = Encoding.UTF8.GetBytes(message);
			
			UdpClient udpSocket = new UdpClient(peer.Address.ToString(), peer.Port);

			udpSocket.Send(bytes, bytes.Length);

			richTextBox1.SelectionColor = Color.Black;

			richTextBox1.AppendText(textBox2.Text + "\n");

			textBox2.Text = "";
		}

		//
		// called when typing in message box
		//
		private void textBox2_TextChanged(object sender, System.EventArgs e)
		{
			PeerData peer = (PeerData) comboBox1.SelectedItem;

			if ((peer.Address != null) && (textBox2.Text.Length > 0))
			{
				button1.Enabled = true;
			}
			else
			{
				button1.Enabled = false;
			}
		}

		//
		// called when peer target changes
		//
		/// <summary>
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void comboBox1_SelectedIndexChanged(object sender, System.EventArgs e)
		{
			PeerData peer = (PeerData) comboBox1.SelectedItem;

			try
			{
				resolver = DNSService.Resolve(0, 0, peer.Name, peer.Type, peer.Domain, new DNSService.ResolveReply(OnResolveReply));
			}
			catch
			{
				MessageBox.Show("Unable to Resolve service", "Error");
				Application.Exit();
			}
		}
	}
}
