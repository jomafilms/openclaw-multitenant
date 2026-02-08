import { LitElement, html, css } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { toast } from "../components/toast.js";
import {
  api,
  User,
  GroupMembership,
  GroupDetails,
  GroupResourceAdmin,
  GroupShareAdmin,
  GroupMember,
  GroupInviteAdmin,
} from "../lib/api.js";

@customElement("ocmt-groups")
export class GroupsPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      max-width: 1000px;
      margin: 0 auto;
    }

    h1 {
      font-size: 1.8rem;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #888;
      margin-bottom: 32px;
    }

    .section {
      margin-bottom: 40px;
    }

    .section h2 {
      font-size: 1.1rem;
      color: #888;
      margin-bottom: 16px;
      text-transform: uppercase;
      letter-spacing: 1px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .badge {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.75rem;
      text-transform: none;
      letter-spacing: 0;
    }

    .badge.admin {
      background: rgba(34, 197, 94, 0.2);
      color: #22c55e;
    }

    .groups-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 16px;
    }

    .group-card {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 20px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .group-card:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(79, 70, 229, 0.3);
    }

    .group-card.selected {
      border-color: #4f46e5;
    }

    .group-header {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 12px;
    }

    .group-name {
      font-weight: 600;
      font-size: 1.1rem;
    }

    .group-slug {
      color: #888;
      font-size: 0.85rem;
      margin-top: 4px;
    }

    .group-description {
      color: #aaa;
      font-size: 0.9rem;
      margin-top: 8px;
    }

    /* Create group form */
    .create-form {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
    }

    .create-form h3 {
      margin-bottom: 16px;
    }

    .form-row {
      display: flex;
      gap: 12px;
      margin-bottom: 12px;
    }

    .form-group {
      flex: 1;
    }

    .form-group label {
      display: block;
      font-size: 0.85rem;
      color: #888;
      margin-bottom: 6px;
    }

    input,
    textarea {
      width: 100%;
      padding: 12px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(255, 255, 255, 0.1);
      color: white;
      font-size: 0.95rem;
      box-sizing: border-box;
    }

    input::placeholder,
    textarea::placeholder {
      color: #666;
    }

    input:focus,
    textarea:focus {
      outline: none;
      border-color: #4f46e5;
    }

    textarea {
      min-height: 80px;
      resize: vertical;
    }

    .btn {
      padding: 10px 20px;
      border-radius: 8px;
      border: none;
      font-size: 0.9rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .btn-primary {
      background: #4f46e5;
      color: white;
    }

    .btn-primary:hover:not(:disabled) {
      background: #4338ca;
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
      color: #ccc;
    }

    .btn-secondary:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.15);
    }

    .btn-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .btn-danger:hover:not(:disabled) {
      background: rgba(239, 68, 68, 0.3);
    }

    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    /* Group detail panel */
    .group-detail {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      padding: 24px;
    }

    .group-detail-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    .group-detail h3 {
      font-size: 1.3rem;
      margin-bottom: 4px;
    }

    .tabs {
      display: flex;
      gap: 4px;
      margin-bottom: 24px;
      background: rgba(255, 255, 255, 0.05);
      padding: 4px;
      border-radius: 8px;
    }

    .tab {
      padding: 10px 20px;
      border: none;
      background: none;
      color: #888;
      cursor: pointer;
      border-radius: 6px;
      transition: all 0.2s;
    }

    .tab:hover {
      color: white;
    }

    .tab.active {
      background: #4f46e5;
      color: white;
    }

    .list-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      margin-bottom: 8px;
    }

    .list-item-info {
      flex: 1;
    }

    .list-item-name {
      font-weight: 500;
    }

    .list-item-meta {
      font-size: 0.85rem;
      color: #888;
      margin-top: 4px;
    }

    .empty-state {
      text-align: center;
      padding: 32px;
      color: #888;
    }

    .empty-state-icon {
      font-size: 2.5rem;
      margin-bottom: 12px;
    }

    .loading {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 40px;
    }

    .spinner {
      width: 32px;
      height: 32px;
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top-color: #4f46e5;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }
  `;

  @property({ type: Object })
  user: User | null = null;

  @state() private groups: GroupMembership[] = [];
  @state() private loading = true;
  @state() private selectedGroup: GroupDetails | null = null;
  @state() private selectedGroupId: string | null = null;
  @state() private detailLoading = false;
  @state() private activeTab: "members" | "resources" | "shares" = "members";

  // Create group form
  @state() private showCreateForm = false;
  @state() private newGroupName = "";
  @state() private newGroupSlug = "";
  @state() private newGroupDescription = "";
  @state() private creating = false;

  // Add resource form
  @state() private showAddResource = false;
  @state() private newResourceName = "";
  @state() private newResourceEndpoint = "";
  @state() private newResourceDescription = "";
  @state() private addingResource = false;

  // Shares
  @state() private shares: GroupShareAdmin[] = [];
  @state() private sharesLoading = false;
  @state() private showAddShare = false;
  @state() private shareUserId = "";
  @state() private shareResourceId = "";
  @state() private addingShare = false;

  // Invite member
  @state() private showInviteMember = false;
  @state() private inviteEmail = "";
  @state() private inviteRole = "member";
  @state() private inviting = false;

  // Pending invites (admin view)
  @state() private pendingInvites: GroupInviteAdmin[] = [];

  connectedCallback() {
    super.connectedCallback();
    this.loadGroups();
  }

  private async loadGroups() {
    this.loading = true;
    try {
      const result = await api.listMyGroups();
      this.groups = result.groups;
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load groups");
    }
    this.loading = false;
  }

  private async loadGroupDetails(groupId: string) {
    this.detailLoading = true;
    this.selectedGroupId = groupId;
    this.shares = [];
    this.pendingInvites = [];
    try {
      this.selectedGroup = await api.getGroup(groupId);
      // Load shares and pending invites if admin
      if (this.selectedGroup.isAdmin) {
        await Promise.all([this.loadShares(groupId), this.loadPendingInvites(groupId)]);
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load group");
    }
    this.detailLoading = false;
  }

  private async loadPendingInvites(groupId: string) {
    try {
      const result = await api.listGroupInvites(groupId);
      // Filter to only pending invites
      this.pendingInvites = result.invites.filter((inv) => inv.status === "pending");
    } catch (err) {
      console.error("Failed to load pending invites:", err);
    }
  }

  private async loadShares(groupId: string) {
    this.sharesLoading = true;
    try {
      const result = await api.listGroupShares(groupId);
      this.shares = result.shares;
    } catch (err) {
      console.error("Failed to load shares:", err);
    }
    this.sharesLoading = false;
  }

  private async handleCreateGroup(e: Event) {
    e.preventDefault();
    if (!this.newGroupName || !this.newGroupSlug) {
      return;
    }

    this.creating = true;
    try {
      await api.createGroup(
        this.newGroupName,
        this.newGroupSlug,
        this.newGroupDescription || undefined,
      );
      toast.success("Group created");
      this.newGroupName = "";
      this.newGroupSlug = "";
      this.newGroupDescription = "";
      this.showCreateForm = false;
      await this.loadGroups();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create group");
    }
    this.creating = false;
  }

  private generateSlug(name: string): string {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "");
  }

  private async handleAddResource(e: Event) {
    e.preventDefault();
    if (!this.selectedGroup || !this.newResourceName || !this.newResourceEndpoint) {
      return;
    }

    this.addingResource = true;
    try {
      await api.createGroupResource(this.selectedGroup.group.id, {
        name: this.newResourceName,
        endpoint: this.newResourceEndpoint,
        description: this.newResourceDescription || undefined,
      });
      toast.success("Resource added");
      this.newResourceName = "";
      this.newResourceEndpoint = "";
      this.newResourceDescription = "";
      this.showAddResource = false;
      await this.loadGroupDetails(this.selectedGroup.group.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to add resource");
    }
    this.addingResource = false;
  }

  private async handleRemoveMember(member: GroupMember) {
    if (!this.selectedGroup) {
      return;
    }
    if (!confirm(`Remove ${member.user_name} from ${this.selectedGroup.group.name}?`)) {
      return;
    }

    try {
      await api.removeGroupMember(this.selectedGroup.group.id, member.user_id);
      toast.success("Member removed");
      await this.loadGroupDetails(this.selectedGroup.group.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to remove member");
    }
  }

  private async handleCancelInvite(invite: GroupInviteAdmin) {
    if (!this.selectedGroup) {
      return;
    }
    if (!confirm(`Cancel invite to ${invite.inviteeEmail}?`)) {
      return;
    }

    try {
      await api.cancelGroupInvite(this.selectedGroup.group.id, invite.id);
      toast.success("Invite cancelled");
      await this.loadPendingInvites(this.selectedGroup.group.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to cancel invite");
    }
  }

  private async handleDeleteResource(resource: GroupResourceAdmin) {
    if (!this.selectedGroup) {
      return;
    }
    if (!confirm(`Delete resource "${resource.name}"? This will revoke all shares.`)) {
      return;
    }

    try {
      await api.deleteGroupResource(this.selectedGroup.group.id, resource.id);
      toast.success("Resource deleted");
      await this.loadGroupDetails(this.selectedGroup.group.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete resource");
    }
  }

  private async handleRevokeShare(share: GroupShareAdmin) {
    if (!this.selectedGroup) {
      return;
    }
    if (!confirm(`Revoke ${share.user_name}'s access to ${share.resource_name}?`)) {
      return;
    }

    try {
      await api.revokeGroupShare(this.selectedGroup.group.id, share.id);
      toast.success("Access revoked");
      await this.loadGroupDetails(this.selectedGroup.group.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to revoke access");
    }
  }

  private async handleAddShare(e: Event) {
    e.preventDefault();
    if (!this.selectedGroup || !this.shareUserId || !this.shareResourceId) {
      return;
    }

    this.addingShare = true;
    try {
      await api.createGroupShare(
        this.selectedGroup.group.id,
        this.shareResourceId,
        this.shareUserId,
        ["read", "write"],
      );
      toast.success("Access granted");
      this.shareUserId = "";
      this.shareResourceId = "";
      this.showAddShare = false;
      await this.loadShares(this.selectedGroup.group.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to grant access");
    }
    this.addingShare = false;
  }

  private async handleInviteMember(e: Event) {
    e.preventDefault();
    if (!this.selectedGroup || !this.inviteEmail) {
      return;
    }

    this.inviting = true;
    try {
      await api.inviteToGroup(this.selectedGroup.group.id, this.inviteEmail, this.inviteRole);
      toast.success("Invitation sent");
      this.inviteEmail = "";
      this.inviteRole = "member";
      this.showInviteMember = false;
      await this.loadGroupDetails(this.selectedGroup.group.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to invite member");
    }
    this.inviting = false;
  }

  render() {
    if (this.loading) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    return html`
      <h1>Groups</h1>
      <p class="subtitle">Manage your groups and shared resources</p>

      <div style="display: flex; gap: 12px; margin-bottom: 24px; flex-wrap: wrap;">
        ${
          this.showCreateForm
            ? ""
            : html`
          <button class="btn btn-primary" @click=${() => (this.showCreateForm = true)}>
            + Create Group
          </button>
        `
        }
        <a href="/group-invites" class="btn btn-secondary" style="text-decoration: none;">
          View Pending Invites
        </a>
      </div>

      ${this.showCreateForm ? this.renderCreateForm() : ""}

      <div class="section">
        <h2>My Groups <span class="badge">${this.groups.length}</span></h2>
        ${
          this.groups.length > 0
            ? html`
          <div class="groups-grid">
            ${this.groups.map((group) => this.renderGroupCard(group))}
          </div>
        `
            : html`
                <div class="empty-state">
                  <div class="empty-state-icon">&#x1F465;</div>
                  <h3>No groups yet</h3>
                  <p>Create a group to share resources with your team, family, or organization</p>
                </div>
              `
        }
      </div>

      ${
        this.selectedGroupId
          ? html`
        <div class="section">
          ${
            this.detailLoading
              ? html`
                  <div class="loading">
                    <div class="spinner"></div>
                  </div>
                `
              : this.selectedGroup
                ? this.renderGroupDetail()
                : ""
          }
        </div>
      `
          : ""
      }
    `;
  }

  private renderCreateForm() {
    return html`
      <div class="create-form">
        <h3>Create Group</h3>
        <form @submit=${this.handleCreateGroup}>
          <div class="form-row">
            <div class="form-group">
              <label>Group Name</label>
              <input
                type="text"
                placeholder="My Team"
                .value=${this.newGroupName}
                @input=${(e: Event) => {
                  this.newGroupName = (e.target as HTMLInputElement).value;
                  if (
                    !this.newGroupSlug ||
                    this.newGroupSlug === this.generateSlug(this.newGroupName.slice(0, -1))
                  ) {
                    this.newGroupSlug = this.generateSlug(this.newGroupName);
                  }
                }}
                required
              />
            </div>
            <div class="form-group">
              <label>Slug (URL-friendly identifier)</label>
              <input
                type="text"
                placeholder="my-team"
                pattern="[a-z0-9-]+"
                .value=${this.newGroupSlug}
                @input=${(e: Event) => (this.newGroupSlug = (e.target as HTMLInputElement).value.toLowerCase())}
                required
              />
            </div>
          </div>
          <div class="form-group" style="margin-bottom: 16px;">
            <label>Description (optional)</label>
            <textarea
              placeholder="What is this group for?"
              .value=${this.newGroupDescription}
              @input=${(e: Event) => (this.newGroupDescription = (e.target as HTMLTextAreaElement).value)}
            ></textarea>
          </div>
          <div style="display: flex; gap: 12px;">
            <button type="submit" class="btn btn-primary" ?disabled=${this.creating}>
              ${this.creating ? "Creating..." : "Create Group"}
            </button>
            <button type="button" class="btn btn-secondary" @click=${() => (this.showCreateForm = false)}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    `;
  }

  private renderGroupCard(group: GroupMembership) {
    const isSelected = this.selectedGroupId === group.group_id;
    const isAdmin = group.role === "admin";

    return html`
      <div
        class="group-card ${isSelected ? "selected" : ""}"
        @click=${() => this.loadGroupDetails(group.group_id)}
      >
        <div class="group-header">
          <div>
            <div class="group-name">${group.group_name}</div>
            <div class="group-slug">/${group.group_slug}</div>
          </div>
          ${
            isAdmin
              ? html`
                  <span class="badge admin">Admin</span>
                `
              : html`
                  <span class="badge">Member</span>
                `
          }
        </div>
      </div>
    `;
  }

  private renderGroupDetail() {
    if (!this.selectedGroup) {
      return "";
    }

    const { group, isAdmin } = this.selectedGroup;

    return html`
      <div class="group-detail">
        <div class="group-detail-header">
          <div>
            <h3>${group.name}</h3>
            <span style="color: #888;">/${group.slug}</span>
            ${group.description ? html`<p class="group-description">${group.description}</p>` : ""}
          </div>
          <button class="btn btn-secondary" @click=${() => {
            this.selectedGroupId = null;
            this.selectedGroup = null;
          }}>
            Close
          </button>
        </div>

        <div class="tabs">
          <button
            class="tab ${this.activeTab === "members" ? "active" : ""}"
            @click=${() => (this.activeTab = "members")}
          >
            Members (${this.selectedGroup.members.length})
          </button>
          <button
            class="tab ${this.activeTab === "resources" ? "active" : ""}"
            @click=${() => (this.activeTab = "resources")}
          >
            Resources (${this.selectedGroup.resources.length})
          </button>
          ${
            isAdmin
              ? html`
            <button
              class="tab ${this.activeTab === "shares" ? "active" : ""}"
              @click=${() => (this.activeTab = "shares")}
            >
              Access Shares
            </button>
          `
              : ""
          }
        </div>

        ${this.activeTab === "members" ? this.renderMembersTab() : ""}
        ${this.activeTab === "resources" ? this.renderResourcesTab() : ""}
        ${this.activeTab === "shares" && isAdmin ? this.renderSharesTab() : ""}
      </div>
    `;
  }

  private renderMembersTab() {
    if (!this.selectedGroup) {
      return "";
    }
    const { members, isAdmin } = this.selectedGroup;

    return html`
      ${
        isAdmin
          ? html`
        ${
          this.showInviteMember
            ? html`
          <div class="create-form" style="margin-bottom: 16px;">
            <form @submit=${this.handleInviteMember}>
              <div class="form-row">
                <div class="form-group">
                  <label>Email Address</label>
                  <input
                    type="email"
                    placeholder="colleague@example.com"
                    .value=${this.inviteEmail}
                    @input=${(e: Event) => (this.inviteEmail = (e.target as HTMLInputElement).value)}
                    required
                  />
                </div>
                <div class="form-group">
                  <label>Role</label>
                  <select
                    style="width: 100%; padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white;"
                    .value=${this.inviteRole}
                    @change=${(e: Event) => (this.inviteRole = (e.target as HTMLSelectElement).value)}
                  >
                    <option value="member">Member</option>
                    <option value="admin">Admin</option>
                  </select>
                </div>
              </div>
              <div style="display: flex; gap: 8px;">
                <button type="submit" class="btn btn-primary" ?disabled=${this.inviting}>
                  ${this.inviting ? "Inviting..." : "Send Invite"}
                </button>
                <button type="button" class="btn btn-secondary" @click=${() => (this.showInviteMember = false)}>
                  Cancel
                </button>
              </div>
            </form>
          </div>
        `
            : html`
          <button class="btn btn-secondary" style="margin-bottom: 16px;" @click=${() => (this.showInviteMember = true)}>
            + Invite Member
          </button>
        `
        }
      `
          : ""
      }

      ${
        members.length > 0 || this.pendingInvites.length > 0
          ? html`
        ${members.map(
          (member) => html`
          <div class="list-item">
            <div class="list-item-info">
              <div class="list-item-name">${member.user_name}</div>
              <div class="list-item-meta">${member.user_email} - ${member.role}</div>
            </div>
            ${
              isAdmin && member.user_id !== this.user?.id
                ? html`
              <button class="btn btn-danger" @click=${() => this.handleRemoveMember(member)}>
                Remove
              </button>
            `
                : ""
            }
          </div>
        `,
        )}
        ${
          isAdmin
            ? this.pendingInvites.map(
                (invite) => html`
          <div class="list-item" style="opacity: 0.7;">
            <div class="list-item-info">
              <div class="list-item-name">
                ${invite.inviteeEmail || "Unknown email"}
                <span class="badge" style="background: rgba(234, 179, 8, 0.2); color: #eab308; margin-left: 8px;">Pending</span>
              </div>
              <div class="list-item-meta">Invited as ${invite.role || "member"} by ${invite.inviterName || "Unknown"}</div>
            </div>
            <button class="btn btn-danger" @click=${() => this.handleCancelInvite(invite)}>
              Revoke
            </button>
          </div>
        `,
              )
            : ""
        }
      `
          : html`
              <div class="empty-state">
                <div class="empty-state-icon">&#x1F465;</div>
                <p>No members yet</p>
              </div>
            `
      }
    `;
  }

  private renderResourcesTab() {
    if (!this.selectedGroup) {
      return "";
    }
    const { resources, isAdmin } = this.selectedGroup;

    return html`
      ${
        isAdmin
          ? html`
        ${
          this.showAddResource
            ? html`
          <div class="create-form" style="margin-bottom: 16px;">
            <form @submit=${this.handleAddResource}>
              <div class="form-row">
                <div class="form-group">
                  <label>Resource Name</label>
                  <input
                    type="text"
                    placeholder="Production API"
                    .value=${this.newResourceName}
                    @input=${(e: Event) => (this.newResourceName = (e.target as HTMLInputElement).value)}
                    required
                  />
                </div>
                <div class="form-group">
                  <label>Endpoint URL</label>
                  <input
                    type="url"
                    placeholder="https://api.example.com"
                    .value=${this.newResourceEndpoint}
                    @input=${(e: Event) => (this.newResourceEndpoint = (e.target as HTMLInputElement).value)}
                    required
                  />
                </div>
              </div>
              <div class="form-group" style="margin-bottom: 12px;">
                <label>Description (optional)</label>
                <input
                  type="text"
                  placeholder="What does this resource provide?"
                  .value=${this.newResourceDescription}
                  @input=${(e: Event) => (this.newResourceDescription = (e.target as HTMLInputElement).value)}
                />
              </div>
              <div style="display: flex; gap: 8px;">
                <button type="submit" class="btn btn-primary" ?disabled=${this.addingResource}>
                  ${this.addingResource ? "Adding..." : "Add Resource"}
                </button>
                <button type="button" class="btn btn-secondary" @click=${() => (this.showAddResource = false)}>
                  Cancel
                </button>
              </div>
            </form>
          </div>
        `
            : html`
          <button class="btn btn-secondary" style="margin-bottom: 16px;" @click=${() => (this.showAddResource = true)}>
            + Add Resource
          </button>
        `
        }
      `
          : ""
      }

      ${
        resources.length > 0
          ? html`
        ${resources.map(
          (resource) => html`
          <div class="list-item">
            <div class="list-item-info">
              <div class="list-item-name">${resource.name}</div>
              <div class="list-item-meta">
                ${resource.description || resource.endpoint}
                ${resource.share_count ? ` - ${resource.connected_count}/${resource.share_count} connected` : ""}
              </div>
            </div>
            ${
              isAdmin
                ? html`
              <button class="btn btn-danger" @click=${() => this.handleDeleteResource(resource)}>
                Delete
              </button>
            `
                : ""
            }
          </div>
        `,
        )}
      `
          : html`
              <div class="empty-state">
                <div class="empty-state-icon">&#x1F4E6;</div>
                <p>No resources configured</p>
              </div>
            `
      }
    `;
  }

  private renderSharesTab() {
    if (!this.selectedGroup) {
      return "";
    }
    const { members, resources } = this.selectedGroup;

    if (this.sharesLoading) {
      return html`
        <div class="loading">
          <div class="spinner"></div>
        </div>
      `;
    }

    return html`
      ${
        this.showAddShare
          ? html`
        <div class="create-form" style="margin-bottom: 16px;">
          <form @submit=${this.handleAddShare}>
            <div class="form-row">
              <div class="form-group">
                <label>Member</label>
                <select
                  style="width: 100%; padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white;"
                  .value=${this.shareUserId}
                  @change=${(e: Event) => (this.shareUserId = (e.target as HTMLSelectElement).value)}
                  required
                >
                  <option value="">Select a member...</option>
                  ${members.map(
                    (m) => html`
                    <option value="${m.user_id}">${m.user_name} (${m.user_email})</option>
                  `,
                  )}
                </select>
              </div>
              <div class="form-group">
                <label>Resource</label>
                <select
                  style="width: 100%; padding: 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(255,255,255,0.1); color: white;"
                  .value=${this.shareResourceId}
                  @change=${(e: Event) => (this.shareResourceId = (e.target as HTMLSelectElement).value)}
                  required
                >
                  <option value="">Select a resource...</option>
                  ${resources.map(
                    (r) => html`
                    <option value="${r.id}">${r.name}</option>
                  `,
                  )}
                </select>
              </div>
            </div>
            <div style="display: flex; gap: 8px;">
              <button type="submit" class="btn btn-primary" ?disabled=${this.addingShare || !this.shareUserId || !this.shareResourceId}>
                ${this.addingShare ? "Granting..." : "Grant Access"}
              </button>
              <button type="button" class="btn btn-secondary" @click=${() => (this.showAddShare = false)}>
                Cancel
              </button>
            </div>
          </form>
        </div>
      `
          : html`
        <button class="btn btn-secondary" style="margin-bottom: 16px;" @click=${() => (this.showAddShare = true)} ?disabled=${members.length === 0 || resources.length === 0}>
          + Grant Access
        </button>
        ${
          members.length === 0 || resources.length === 0
            ? html`
                <p style="color: #888; font-size: 0.85rem; margin-bottom: 16px">
                  Add members and resources first to grant access.
                </p>
              `
            : ""
        }
      `
      }

      ${
        this.shares.length > 0
          ? html`
        ${this.shares.map(
          (share) => html`
          <div class="list-item">
            <div class="list-item-info">
              <div class="list-item-name">${share.user_name} → ${share.resource_name}</div>
              <div class="list-item-meta">
                ${this.formatPermissions(share.permissions)}
                - ${share.status === "connected" ? "✓ Connected" : "○ Granted"}
                - ${new Date(share.granted_at).toLocaleDateString()}
              </div>
            </div>
            <button class="btn btn-danger" @click=${() => this.handleRevokeShare(share)}>
              Revoke
            </button>
          </div>
        `,
        )}
      `
          : html`
              <div class="empty-state">
                <div class="empty-state-icon">&#x1F511;</div>
                <p>No access shares yet</p>
                <p style="font-size: 0.85rem; margin-top: 8px">
                  Grant members access to resources so their agents can use them.
                </p>
              </div>
            `
      }
    `;
  }

  // Helper to format permissions (handles both array and object formats)
  private formatPermissions(permissions: string[] | Record<string, boolean> | null): string {
    if (!permissions) {
      return "none";
    }
    if (Array.isArray(permissions)) {
      return permissions.join(", ");
    }
    // Object format: {read: true, write: false} -> "read"
    return (
      Object.entries(permissions)
        .filter(([_, enabled]) => enabled)
        .map(([perm]) => perm)
        .join(", ") || "none"
    );
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "ocmt-groups": GroupsPage;
  }
}
