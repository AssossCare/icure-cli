import fetch from 'node-fetch'
import {
	ContactDto,
	Filter,
	ImportResultDto,
	ListOfIdsDto,
	MedicationSchemeExportInfoDto,
	PatientDto,
	UserDto
} from 'icc-api'
import { chunk, flatMap, get, assign } from 'lodash'
import { Api } from './api'

import * as colors from 'colors/safe'
import { Args, CommandInstance } from 'vorpal'
import StatusEnum = UserDto.StatusEnum
import TypeEnum = UserDto.TypeEnum

require('node-json-color-stringify')

const path = require('path')
const fs = require('fs')
const vorpal = new (require('vorpal'))()

// TODO use a logger
// TODO patient merges
// TODO more examples, with invoices/health elements/contacts, at first level

const tmp = require('os').tmpdir()
console.log('Tmp dir: ' + tmp)
;(global as any).localStorage = new (require('node-localstorage').LocalStorage)(tmp, 5 * 1024 * 1024 * 1024)
;(global as any).Storage = ''

const options = {
	username: 'abdemo',
	password: 'knalou',
	host: 'https://backendb.svc.icure.cloud/rest/v1',
	repoUsername: null,
	repoPassword: null,
	repoHost: null,
	repoHeader: {}
}

let api = new Api(options.host, { Authorization: `Basic ${Buffer.from(`${options.username}:${options.password}`).toString('base64')}` }, fetch as any)
let latestImport: ImportResultDto
let latestExport: ArrayBufferLike

vorpal
	.command('login <username> <password> [host]', 'Login to iCure')
	.action(async function(this: CommandInstance, args: Args) {
		options.username = args.username
		options.password = args.password
		args.host && (options.host = args.host)

		api = new Api(options.host, { Authorization: `Basic ${Buffer.from(`${options.username}:${options.password}`).toString('base64')}` }, fetch as any)
	})

vorpal
	.command('pki <hcpId> <key>', 'Private Key Import')
	.action(async function(this: CommandInstance, args: Args) {
		const hcpId = args.hcpId
		const key = args.key

		await api.cryptoicc.loadKeyPairsAsTextInBrowserLocalStorage(hcpId, api.cryptoicc.utils.hex2ua(key))
		if (await api.cryptoicc.checkPrivateKeyValidity(await api.hcpartyicc.getHealthcareParty(hcpId))) {
			this.log('Key is valid')
		} else {
			this.log('Key is invalid')
		}
	})

vorpal
	.command('lpkis', 'List Private Keys')
	.action(async function(this: CommandInstance, args: Args) {
		const users = (await api.usericc.listUsers(undefined, undefined, undefined)).rows
		users.reduce(async (p: Promise<any>, u: UserDto) => {
			await p
			if (u.healthcarePartyId) {
				const hcp = await api.hcpartyicc.getHealthcareParty(u.healthcarePartyId)
				try {
					if (hcp.publicKey && await api.cryptoicc.checkPrivateKeyValidity(hcp)) {
						this.log(`${colors.green('√')} ${hcp.id}: ${hcp.firstName} ${hcp.lastName}`)
					} else {
						this.log(`${colors.red('X')} ${hcp.id}: ${hcp.firstName} ${hcp.lastName}`)
					}
				} catch (e) {
					this.log(`X ${hcp.id}: ${hcp.firstName} ${hcp.lastName}`)
				}
			}
		}, Promise.resolve())
	})

vorpal
	.command('whoami', 'Logged user info')
	.action(async function(this: CommandInstance, args: Args) {
		this.log((await api.usericc.getCurrentUser()).login + '@' + options.host)
	})

vorpal
	.command('pat [name] [first]', 'Logged user info')
	.action(async function(this: CommandInstance, args: Args) {
		this.log(JSON.stringify((await api.patienticc.fuzzySearchWithUser(await api.usericc.getCurrentUser(), args.first, args.name, undefined))
			.map((p: PatientDto) => ({ id: p.id, lastName: p.lastName, firstName: p.firstName }))))
	})

vorpal
	.command('missingdel <entity> [hcpIds...]', 'Get list of mismatch access on list of hcp id')
	.action(async function(this: CommandInstance, args: Args) {
		const all = {}
		const byHcp = {} as any
		let user = await api.usericc.getCurrentUser()

		await Promise.all(args.hcpIds.map(async (hcpId: string) => {
			const batchIds = await api.contacticc.matchBy(new Filter({
				healthcarePartyId: hcpId,
				$type: 'ContactByHcPartyTagCodeDateFilter'
			}))
			const batch = batchIds
				.reduce((acc: { [key: string]: number }, id: string) => {
					acc[id] = 1
					return acc
				}, {})
			byHcp[hcpId] = batch
			Object.assign(all, batch)
		}))

		const incomplete = Object.keys(all).filter(id => Object.keys(byHcp).some(k => !byHcp[k][id]))

		const patIds = await contactsToPatientIds(user.healthcarePartyId, await api.contacticc.getContactsWithUser(user, new ListOfIdsDto({ ids: incomplete })))

		this.log(JSON.stringify(patIds))
	})

vorpal
	.command('share <hcpId> [patIds...]', 'Share with hcp ids')
	.action(async function(this: CommandInstance, args: Args) {
		let user = await api.usericc.getCurrentUser()

		const hcpId = args.hcpId
		const ids = args.patIds

		const patients = await api.patienticc.getPatientsWithUser(user, new ListOfIdsDto({ ids })) // Get them to fix them

		this.log(JSON.stringify((await patients.reduce(async (p: Promise<any>, pat: PatientDto) => {
			const prev = await p
			try {
				return prev.concat([await api.patienticc.share(user, pat.id!, user.healthcarePartyId!, [hcpId], { [hcpId]: ['all'] })])
			} catch (e) {
				console.log(e)
				return prev
			}
		}
			, Promise.resolve([]))).map((x: any) => x.statuses), undefined, ' '))
	})

vorpal
	.command('shareall [hcpIds...]', 'Share with hcp ids')
	.action(async function(this: CommandInstance, args: Args) {
		let user = await api.usericc.getCurrentUser()

		const hcpIds = args.hcpIds as string[]
		const allIds = await api.patienticc.listPatientsIds(user.healthcarePartyId, undefined, undefined, 20000)

		chunk(allIds.rows, 100).reduce(async (p, ids) => {
			await p
			const patients = await api.patienticc.getPatientsWithUser(user, new ListOfIdsDto({ ids })) // Get them to fix them

			this.log(JSON.stringify((await patients.reduce(async (p: Promise<any>, pat: PatientDto) => {
				const prev = await p
				try {
					return prev.concat([await api.patienticc.share(user, pat.id!, user.healthcarePartyId!, hcpIds, hcpIds.reduce((map,hcpId) => Object.assign(map, { [hcpId]: ['all'] }), {}))])
				} catch (e) {
					console.log(e)
					return prev
				}
			}
				, Promise.resolve([]))).map((x: any) => x.statuses), undefined, ' '))

		}, Promise.resolve())

	})

vorpal
	.command('imp-ms [path]', 'Convert local medication scheme xml to services')
	.action(async function(this: CommandInstance, args: Args) {
		const user = await api.usericc.getCurrentUser()
		const doc = await api.documenticc.createDocument({
			id: api.cryptoicc.randomUuid(),
			author: user.id,
			responsible: user.healthcarePartyId
		})
		await api.documenticc.setAttachment(doc.id, undefined, fs.readFileSync(args.path).buffer)
		latestImport = (await api.bekmehricc.importMedicationScheme(doc.id, undefined, true, undefined, 'fr', {}))[0]
		this.log(JSON.stringify(latestImport))
	})

vorpal
	.command('exp-ms', 'Export medication scheme from latest import to xml')
	.action(async function(this: CommandInstance, args: Args) {
		latestExport = await api.bekmehricc.generateMedicationSchemeExport(latestImport.patient!.id!, 'fr', undefined, new MedicationSchemeExportInfoDto({
			services: flatMap(latestImport.ctcs!.map(c => c.services))
		}))
		this.log(api.cryptoicc.utils.ua2utf8(latestExport))
	})

vorpal
	.command('createUser <firstName> <lastName> <email> [ssin] [nihii] [parentId]', 'This function create user in db. firstName, lastName and email are mandatory. Ssin, nihii and parent id are optional')
	.action(async function(this: CommandInstance, args: Args) {
		this.log('FirstName: ' + args.firstName + ' LastName: ' + args.lastName + ' Email: ' + args.email + ' Ssin' + args.ssin + ' Nihii: ' + args.nihii + ' ParentId: ' + args.parentId)
		let hcp = await api.hcpartyicc.createHealthcareParty({
			name: get(args, 'firstName', null) + ' ' + get(args, 'lastName', null),
			lastName: get(args, 'lastName', null),
			firstName: get(args, 'firstName', null),
			nihii: get(args, 'nihii', ''),
			ssin: get(args, 'ssin', ''),
			parentId: get(args, 'parentId', null)
		})
		let delegations = {
			all: [hcp.id]
		}
		if (args.delegationTypeForParent === 'all') {
			delegations.all.push(hcp.parentId)
		}
		let user = await api.usericc.createUser({
			healthcarePartyId: hcp.id,
			name: get(args, 'firstName', null) + ' ' + get(args, 'lastName', null),
			email: get(args, 'email', null),
			applicationTokens: { tmpFirstLogin: api.cryptoicc.randomUuid() },
			status: StatusEnum.ACTIVE,
			type: TypeEnum.Database,
			autoDelegations: delegations
		})
		this.log('UserId: ' + user.id + ' Token: ' + user.applicationTokens.tmpFirstLogin)
	})

vorpal
	.delimiter('icure-cli$')
	.history('icrprt')
	.show()

async function contactsToPatientIds(hcpartyId: string, contacts: ContactDto[]): Promise<string[]> {
	try {
		const extractPromises = contacts.map((ctc: ContactDto) => {
			return api.cryptoicc.extractKeysFromDelegationsForHcpHierarchy(hcpartyId, ctc.id || '', ctc.cryptedForeignKeys || {}).catch(() => ({ extractedKeys: [] }))
		})
		const extracted = await Promise.all(extractPromises)
		return [...new Set(flatMap(extracted, it => it.extractedKeys))]
	} catch (error) {
		console.error('Error while converting contacts to patient ids')
		console.error(error)
		return Promise.reject()
	}
}
